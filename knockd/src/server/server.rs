use crate::sequence::SequenceDetector;
use log::error;
use pnet::datalink::Channel::Ethernet;
use pnet::datalink::{self, NetworkInterface};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::Packet;

pub struct Server {
    interface_name: String,
    detector: Box<dyn SequenceDetector>,
}

impl Server {
    pub fn new(interface: String, detector: Box<dyn SequenceDetector>) -> Box<Server> {
        Box::new(Server {
            interface_name: interface,
            detector,
        })
    }

    pub fn start(&mut self) {
        // Start the sequence detector thread
        self.detector.start();

        let interface = datalink::interfaces()
            .into_iter()
            .find(|iface: &NetworkInterface| iface.name == self.interface_name)
            .expect("Failed to get interface");

        // Create a channel to receive on
        let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
            Ok(Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => panic!("Unhandled channel type"),
            Err(e) => panic!(
                "An error occurred when creating the data link channel: {}",
                e
            ),
        };

        loop {
            match rx.next() {
                Ok(packet) => {
                    let Some(packet) = EthernetPacket::new(packet) else {
                        // Skip malformed or truncated frames instead of crashing.
                        continue;
                    };
                    match packet.get_ethertype() {
                        EtherTypes::Ipv4 => {
                            if let Some(header) =
                                pnet::packet::ipv4::Ipv4Packet::new(packet.payload())
                            {
                                if header.get_next_level_protocol() == IpNextHeaderProtocols::Tcp {
                                    if let Some(tcp) = TcpPacket::new(header.payload()) {
                                        // Check for SYN flag and that ACK flag is not set
                                        if tcp.get_flags() & pnet::packet::tcp::TcpFlags::SYN != 0
                                            && tcp.get_flags() & pnet::packet::tcp::TcpFlags::ACK
                                                == 0
                                        {
                                            self.detector.add_sequence(
                                                header.get_source(),
                                                tcp.get_destination() as i32,
                                            );
                                        }
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                }
                Err(e) => {
                    error!("An error occurred while reading: {}", e);
                }
            }
        }
    }
}
