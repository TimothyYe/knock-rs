use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::config::Config;
use crate::executor;
use crate::sequence::SequenceDetector;
use log::{error, info};

#[derive(Debug)]
pub struct PortSequenceDetector {
    timeout: u64,
    sequence_set: HashSet<i32>,
    sequence_rules: HashMap<String, Vec<i32>>,
    rules_map: HashMap<String, String>,
    client_sequences: Arc<Mutex<HashMap<Ipv4Addr, Vec<i32>>>>,
    client_timeout: Arc<Mutex<HashMap<Ipv4Addr, u64>>>,
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
            client_sequences: Arc::new(Mutex::new(HashMap::new())),
            client_timeout: Arc::new(Mutex::new(HashMap::new())),
        }
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

        {
            let mut client_sequence = self.client_sequences.lock().unwrap();
            let client_sequence = client_sequence.entry(client_ip).or_default();
            client_sequence.push(sequence);

            // get the current time stamp
            let mut client_timeout = self.client_timeout.lock().unwrap();
            let current_time = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            client_timeout.insert(client_ip, current_time);
        }

        self.match_sequence(client_ip);
    }

    fn match_sequence(&mut self, client_ip: Ipv4Addr) -> bool {
        // Check if the current sequence matches any of the rules
        let mut client_sequence = self.client_sequences.lock().unwrap();
        let client_sequence = client_sequence.get_mut(&client_ip);
        if let Some(sequence) = client_sequence {
            for (name, rule) in &self.sequence_rules {
                if sequence.ends_with(&rule) {
                    info!("Matched knock sequence: {:?} from: {}", rule, client_ip);
                    // clear the sequence
                    sequence.clear();

                    // execute the command
                    let command = self.rules_map.get(name).unwrap();
                    let formatted_cmd = command.replace("%IP%", &client_ip.to_string());
                    info!("Executing command: {}", formatted_cmd);

                    // format the command with the client ip
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
        }

        false
    }

    fn start(&mut self) {
        let client_sequences = Arc::clone(&self.client_sequences);
        let client_timeout = Arc::clone(&self.client_timeout);
        let timeout = self.timeout;

        thread::spawn(move || loop {
            thread::sleep(std::time::Duration::from_millis(200));

            let client_sequences_guard = match client_sequences.lock() {
                Ok(guard) => guard,
                Err(poisoned) => {
                    error!("Error: {:?}", poisoned);
                    continue;
                }
            };

            let client_timeout_guard = match client_timeout.lock() {
                Ok(guard) => guard,
                Err(poisoned) => {
                    error!("Error: {:?}", poisoned);
                    continue;
                }
            };

            let mut client_sequences = client_sequences_guard;
            let mut client_timeout = client_timeout_guard;

            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();

            let clients_to_remove: Vec<_> = client_timeout
                .iter()
                .filter_map(|(client_ip, _)| {
                    let last_time = client_timeout.get(client_ip).unwrap();
                    if now - last_time > timeout {
                        return Some(client_ip.clone());
                    }
                    None
                })
                .collect();

            for client_ip in clients_to_remove {
                client_sequences.remove(&client_ip);
                client_timeout.remove(&client_ip);
            }
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
        let client_sequences = detector.client_sequences.lock().unwrap();
        assert_eq!(client_sequences.get(&client_ip), Some(&vec![3]));
    }

    #[test]
    fn test_add_sequence_with_timeout() {
        let config = create_config();
        let mut detector = PortSequenceDetector::new(config);
        detector.start();
        let client_ip = Ipv4Addr::new(127, 0, 0, 1);
        detector.add_sequence(client_ip, 3);
        thread::sleep(Duration::from_secs(4));
        let client_sequences = detector.client_sequences.lock().unwrap();
        assert_eq!(client_sequences.get(&client_ip), None);
    }

    #[test]
    fn test_add_none_existing_sequence() {
        let config = create_config();
        let mut detector = PortSequenceDetector::new(config);
        let client_ip = Ipv4Addr::new(127, 0, 0, 1);
        detector.add_sequence(client_ip, 9);
        let client_sequences = detector.client_sequences.lock().unwrap();
        assert_eq!(client_sequences.get(&client_ip), None);
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
        assert_eq!(detector.match_sequence(client_ip), false);
        let client_sequences = detector.client_sequences.lock().unwrap();
        assert_eq!(client_sequences.get(&client_ip).unwrap().len(), 0);
    }
}
