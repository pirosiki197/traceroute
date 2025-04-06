use std::net::UdpSocket;
use std::time::Duration;

use pnet::packet::icmp::IcmpTypes;
use pnet::packet::icmp::destination_unreachable::IcmpCodes::DestinationPortUnreachable as PORT_UNREACHABLE;
use pnet::packet::icmp::time_exceeded::IcmpCodes::TimeToLiveExceededInTransit as TTL_EXCEEDED;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::transport::TransportChannelType::Layer4;
use pnet::transport::{self, TransportProtocol};

fn main() -> std::io::Result<()> {
    let ip_addr = std::env::args()
        .nth(1)
        .expect("Please provide an IP address");
    let ip_addr = ip_addr
        .parse::<std::net::IpAddr>()
        .expect("Invalid IP address");

    let socket = UdpSocket::bind("0.0.0.0:0")?;

    let mut ttl = 1;
    let max_ttl = 30;

    println!("traceroute to {}", ip_addr);

    while ttl <= max_ttl {
        socket.set_ttl(ttl).unwrap();
        socket.send_to(&[0; 60], (ip_addr, 33434))?;

        let (_, mut rx) = transport::transport_channel(
            1024,
            Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Icmp)),
        )?;
        let mut iter = transport::icmp_packet_iter(&mut rx);

        let Some((packet, addr)) = iter.next_with_timeout(Duration::from_secs(3))? else {
            println!("No packet received");
            return Ok(());
        };
        println!("{:<2} {}", ttl, addr);

        let icmp_type = packet.get_icmp_type();
        let icmp_code = packet.get_icmp_code();
        match (icmp_type, icmp_code) {
            (IcmpTypes::TimeExceeded, TTL_EXCEEDED) => (),
            (IcmpTypes::DestinationUnreachable, PORT_UNREACHABLE) => {
                println!("Reached destination: {}", addr);
                break;
            }
            _ => {
                println!(
                    "Received other ICMP message: type {:?}, code {:?}",
                    icmp_type, icmp_code
                );
                break;
            }
        }

        ttl += 1;
    }

    Ok(())
}
