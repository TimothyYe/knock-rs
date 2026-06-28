use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::config::Config;
use crate::executor;
use crate::sequence::SequenceDetector;
use log::{error, info};

/// Per-client knock progress: the ports seen so far and the timestamp of the
/// most recent one, used to expire stale partial sequences.
#[derive(Debug)]
struct ClientState {
    sequence: Vec<i32>,
    last_seen: u64,
}

#[derive(Debug)]
pub struct PortSequenceDetector {
    timeout: u64,
    sequence_set: HashSet<i32>,
    sequence_rules: HashMap<String, Vec<i32>>,
    rules_map: HashMap<String, String>,
    clients: Arc<Mutex<HashMap<Ipv4Addr, ClientState>>>,
}

impl PortSequenceDetector {
    #[must_use]
    pub fn new(config: Config) -> PortSequenceDetector {
        let mut sequence_rules = HashMap::new();
        for rule in config.rules.clone() {
            sequence_rules.insert(rule.name, rule.sequence);
        }

        let mut sequence_set = HashSet::new();
        for rule in config.rules.clone() {
            for sequence in rule.sequence {
                sequence_set.insert(sequence);
            }
        }

        let mut rules_map = HashMap::new();
        for rule in config.rules {
            rules_map.insert(rule.name, rule.command);
        }

        PortSequenceDetector {
            timeout: config.timeout,
            sequence_set,
            sequence_rules,
            rules_map,
            clients: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Checks the client's recorded sequence against the configured rules while
    /// the map is already locked, executing the first matching rule's command.
    /// Returns whether a rule matched.
    fn match_locked(
        &self,
        clients: &mut HashMap<Ipv4Addr, ClientState>,
        client_ip: Ipv4Addr,
    ) -> bool {
        let Some(state) = clients.get_mut(&client_ip) else {
            return false;
        };

        for (name, rule) in &self.sequence_rules {
            if state.sequence.ends_with(rule) {
                info!("Matched knock sequence: {:?} from: {}", rule, client_ip);
                // clear the sequence
                state.sequence.clear();

                // execute the command, substituting the client IP
                let command = self.rules_map.get(name).unwrap();
                let formatted_cmd = command.replace("%IP%", &client_ip.to_string());
                info!("Executing command: {}", formatted_cmd);

                match executor::execute_command(&formatted_cmd) {
                    Ok(_) => {
                        info!("Command executed successfully");
                    }
                    Err(e) => {
                        error!("Error executing command: {:?}", e);
                    }
                }

                return true;
            }
        }

        false
    }
}

impl SequenceDetector for PortSequenceDetector {
    fn add_sequence(&mut self, client_ip: Ipv4Addr, sequence: i32) {
        // check if the sequence is in the set
        if !self.sequence_set.contains(&sequence) {
            return;
        }

        info!(
            "SYN packet detected from: {} to target port: {}",
            client_ip, sequence
        );

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Record the port and match against the rules under a single lock.
        let mut clients = self.clients.lock().unwrap();
        let state = clients.entry(client_ip).or_insert_with(|| ClientState {
            sequence: Vec::new(),
            last_seen: now,
        });
        state.sequence.push(sequence);
        state.last_seen = now;

        self.match_locked(&mut clients, client_ip);
    }

    fn start(&mut self) {
        let clients = Arc::clone(&self.clients);
        let timeout = self.timeout;

        thread::spawn(move || loop {
            thread::sleep(std::time::Duration::from_millis(200));

            let mut clients = match clients.lock() {
                Ok(guard) => guard,
                Err(poisoned) => {
                    error!("Error: {:?}", poisoned);
                    continue;
                }
            };

            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();

            // Drop clients whose last knock is older than the timeout.
            // saturating_sub guards against a backwards clock step.
            clients.retain(|_, state| now.saturating_sub(state.last_seen) <= timeout);
        });

        info!("Port sequence detector thread started...");
    }
}

#[cfg(test)]
mod tests {
    use std::{thread, time::Duration};

    use super::*;

    fn create_config() -> Config {
        Config {
            interface: "enp3s0".to_string(),
            timeout: 2,
            rules: vec![
                crate::config::config::Rule {
                    name: "enable ssh".to_string(),
                    sequence: vec![1, 2, 3],
                    command: "ls -lh".to_string(),
                },
                crate::config::config::Rule {
                    name: "disable ssh".to_string(),
                    sequence: vec![3, 5, 6],
                    command: "free -g".to_string(),
                },
            ],
        }
    }

    #[test]
    fn test_new() {
        let config = create_config();
        let detector = PortSequenceDetector::new(config);
        assert_eq!(detector.sequence_set.len(), 5);
        assert_eq!(detector.sequence_rules.len(), 2);
        assert_eq!(detector.timeout, 2);
    }

    #[test]
    fn test_add_sequence() {
        let config = create_config();
        let mut detector = PortSequenceDetector::new(config);
        let client_ip = Ipv4Addr::new(127, 0, 0, 1);
        detector.add_sequence(client_ip, 3);
        let clients = detector.clients.lock().unwrap();
        assert_eq!(clients.get(&client_ip).unwrap().sequence, vec![3]);
    }

    #[test]
    fn test_add_sequence_with_timeout() {
        let config = create_config();
        let mut detector = PortSequenceDetector::new(config);
        detector.start();
        let client_ip = Ipv4Addr::new(127, 0, 0, 1);
        detector.add_sequence(client_ip, 3);
        thread::sleep(Duration::from_secs(4));
        let clients = detector.clients.lock().unwrap();
        assert!(clients.get(&client_ip).is_none());
    }

    #[test]
    fn test_add_none_existing_sequence() {
        let config = create_config();
        let mut detector = PortSequenceDetector::new(config);
        let client_ip = Ipv4Addr::new(127, 0, 0, 1);
        detector.add_sequence(client_ip, 9);
        let clients = detector.clients.lock().unwrap();
        assert!(clients.get(&client_ip).is_none());
    }

    #[test]
    fn test_match_sequence() {
        let config = create_config();
        let mut detector = PortSequenceDetector::new(config);
        let client_ip = Ipv4Addr::new(127, 0, 0, 1);
        detector.add_sequence(client_ip, 1);
        detector.add_sequence(client_ip, 3);
        detector.add_sequence(client_ip, 5);
        detector.add_sequence(client_ip, 6);
        // The [3, 5, 6] suffix matches the "disable ssh" rule, which clears the
        // recorded sequence after running its command.
        let clients = detector.clients.lock().unwrap();
        assert_eq!(clients.get(&client_ip).unwrap().sequence.len(), 0);
    }
}
