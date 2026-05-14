use pcap::{Active, Capture, Device};
use pnet::packet::{
    ethernet::{EtherTypes, EthernetPacket},
    ipv4::Ipv4Packet,
};
use pnet_packet::{Packet, tcp::TcpPacket};
use pnet_packet::{ipv6::Ipv6Packet, tcp::TcpFlags};
use std::sync::Arc;
use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
};
use tracing::info;

use crate::tcp::tcp::{OnStreamPacket, StreamKey, TcpPacketWithAddr, TcpSession, TcpSessionKey};

pub struct TcpPcapEngine {
    pub device: String,
    pub bpf: String,
    pub link_type: pcap::Linktype,
    pub server_ports: HashSet<u16>,
    sessions: HashMap<TcpSessionKey, TcpSession>,
    pub on_stream_packet: OnStreamPacket,
}

impl TcpPcapEngine {
    pub fn new<F>(device: impl Into<String>, bpf: impl Into<String>, on_stream_packet: F) -> Self
    where
        F: Fn(StreamKey, &[u8]) + Send + Sync + 'static,
    {
        Self {
            device: device.into(),
            bpf: bpf.into(),
            link_type: pcap::Linktype::NULL,
            server_ports: HashSet::new(),
            sessions: HashMap::new(),
            on_stream_packet: Arc::new(on_stream_packet),
        }
    }

    pub fn start(&mut self) -> anyhow::Result<()> {
        let _ = Device::list()?
            .into_iter()
            .find(|d| d.name == self.device.as_str())
            .expect(format!("{} not found", self.device.as_str()).as_str());

        let mut cap: Capture<Active> = Capture::from_device(self.device.as_str())?
            .promisc(true)
            .snaplen(65535)
            .timeout(100)
            .open()?;

        cap.filter(&self.bpf, true)?;
        self.link_type = cap.get_datalink();
        info!(
            "Device:{}, link_type:{:?}, waiting for data.",
            self.device.as_str(),
            self.link_type
        );
        loop {
            let packet = match cap.next_packet() {
                Ok(pkt) => pkt,
                Err(pcap::Error::TimeoutExpired) => continue,
                Err(e) => return Err(e.into()),
            };

            self.handle_packet(packet.data);
        }
    }

    fn handle_packet(&mut self, data: &[u8]) {
        let ip_data = match self.link_type {
            pcap::Linktype::ETHERNET => {
                if let Some(eth) = EthernetPacket::new(data) {
                    match eth.get_ethertype() {
                        EtherTypes::Ipv4 => &data[14..],
                        EtherTypes::Ipv6 => &data[14..],
                        EtherTypes::Vlan => {
                            todo!()
                        }
                        _ => {
                            return;
                        }
                    }
                } else {
                    return;
                }
            }
            pcap::Linktype::LINUX_SLL => {
                // SLL 头 16 字节
                let protocol = u16::from_be_bytes([data[14], data[15]]);
                match protocol {
                    0x0800 => &data[16..], // IPv4
                    0x86DD => &data[16..], // IPv6
                    _ => return,
                }
            }
            pcap::Linktype::NULL => {
                let af = u32::from_ne_bytes(data[0..4].try_into().unwrap());
                match af {
                    2 | 30 => &data[4..],
                    _ => return,
                }
            }
            pcap::Linktype::RAW => data,
            _ => {
                return;
            }
        };
        self.handle_ip_packet(ip_data);
    }

    fn handle_ip_packet(&mut self, ip_data: &[u8]) {
        if ip_data.is_empty() {
            return;
        }
        match ip_data[0] >> 4 {
            4 => {
                if let Some(ip) = Ipv4Packet::new(ip_data) {
                    self.handle_tcp_packet(
                        IpAddr::V4(ip.get_source()),
                        IpAddr::V4(ip.get_destination()),
                        &ip,
                    );
                }
            }
            6 => {
                if let Some(ip) = Ipv6Packet::new(ip_data) {
                    self.handle_tcp_packet(
                        IpAddr::V6(ip.get_source()),
                        IpAddr::V6(ip.get_destination()),
                        &ip,
                    );
                }
            }
            _ => {
                return;
            }
        }
    }

    fn handle_tcp_packet<P: pnet_packet::Packet>(
        &mut self,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        ip_packet: &P,
    ) {
        let payload = ip_packet.payload();
        if let Some(tcp) = TcpPacket::new(payload) {
            let src_port = tcp.get_source();
            let dst_port = tcp.get_destination();
            info!(
                "TCP packet: [{}:{} -> {}:{}], seq :{}, ack :{}",
                src_ip,
                src_port,
                dst_ip,
                dst_port,
                tcp.get_sequence(),
                tcp.get_acknowledgement()
            );
            let tpw = TcpPacketWithAddr::new(src_ip, dst_ip, tcp);
            self.on_tcp_packet(&tpw);
        }
    }

    fn on_tcp_packet(&mut self, pkt: &TcpPacketWithAddr<'_>) {
        println!("got tcp payload: {} bytes", pkt.origin.payload().len());
        let flags = pkt.origin.get_flags();
        if flags & TcpFlags::SYN != 0 && flags & TcpFlags::ACK == 0 {
            //第一次挥手
            //记录server端口
            self.server_ports.insert(pkt.origin.get_destination());
            self.add_session(
                pkt.src_ip.clone(),
                pkt.origin.get_source(),
                pkt.dst_ip.clone(),
                pkt.origin.get_destination(),
            );
        } else {
            let session_id = if self.server_ports.contains(&pkt.origin.get_destination()) {
                //c -> s
                TcpSessionKey::new(
                    pkt.src_ip.clone(),
                    pkt.origin.get_source(),
                    pkt.dst_ip.clone(),
                    pkt.origin.get_destination(),
                )
            } else {
                //s -> c
                TcpSessionKey::new(
                    pkt.dst_ip.clone(),
                    pkt.origin.get_destination(),
                    pkt.src_ip.clone(),
                    pkt.origin.get_source(),
                )
            };
            if let Some(session) = self.sessions.get_mut(&session_id) {
                session.update(&pkt.origin);
            }
        }
    }

    fn add_session(
        &mut self,
        client_ip: IpAddr,
        client_port: u16,
        server_ip: IpAddr,
        server_port: u16,
    ) -> &mut TcpSession {
        self.sessions
            .entry(TcpSessionKey {
                client_ip,
                client_port,
                server_ip,
                server_port,
            })
            .or_insert_with(|| {
                TcpSession::new(
                    client_ip.clone(),
                    client_port,
                    server_ip.clone(),
                    server_port,
                    self.on_stream_packet.clone(),
                )
            })
    }
}
