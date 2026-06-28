use std::net::Ipv4Addr;

pub use port_sequence::PortSequenceDetector;

mod port_sequence;

pub trait SequenceDetector {
    fn start(&mut self);
    fn add_sequence(&mut self, client_ip: Ipv4Addr, sequence: i32);
}
