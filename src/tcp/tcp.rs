use std::{collections::HashMap, fmt, net::IpAddr};
use std::fmt::Formatter;
use pnet_packet::{
    Packet,
    tcp::{TcpFlags, TcpPacket},
};
use tracing::{debug, info};

pub type OnStreamPacket = fn(StreamKey, &[u8]);
pub struct TcpPacketWithAddr<'a> {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub origin: TcpPacket<'a>,
}

impl<'a> TcpPacketWithAddr<'a> {
    pub fn new(src_ip: IpAddr, dst_ip: IpAddr, tcp_packet: TcpPacket<'a>) -> Self {
        Self {
            src_ip,
            dst_ip,
            origin: tcp_packet,
        }
    }
}

impl<'a> From<TcpPacketWithAddr<'a>> for StreamKey {
    fn from(value: TcpPacketWithAddr<'a>) -> Self {
        Self{
            src_ip: value.src_ip,
            src_port: value.origin.get_source(),
            dst_ip: value.dst_ip,
            dst_port: value.origin.get_destination(),
        }
    }
}

#[derive(Hash, Eq, PartialEq, Clone, Debug)]
pub struct TcpSessionKey {
    pub client_ip: IpAddr,
    pub client_port: u16,
    pub server_ip: IpAddr,
    pub server_port: u16,
}

impl TcpSessionKey {
    pub fn new(client_ip: IpAddr, client_port: u16, server_ip: IpAddr, server_port: u16) -> Self {
        Self {
            client_ip,
            client_port,
            server_ip,
            server_port,
        }
    }
}

impl fmt::Display for TcpSessionKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{} <-> {},{}", self.client_ip, self.client_port, self.server_ip, self.server_port)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpState {
    SynSent,     // SYN
    SynReceived, // SYN + ACK
    Established, // ACK（三次握手完成）
    FinWait,     // FIN
    Closed,      // FIN + ACK
}

pub struct TcpSession {
    pub session_id: TcpSessionKey,
    pub server_port: u16,
    pub state: TcpState,
    client_to_server: TcpReassembly,
    server_to_client: TcpReassembly,
}

impl TcpSession {
    pub fn new(
        client_ip: IpAddr,
        client_port: u16,
        server_ip: IpAddr,
        server_port: u16,
        on_stream_packet: OnStreamPacket,
    ) -> Self {
        let session_id = TcpSessionKey {
            client_ip,
            client_port,
            server_ip,
            server_port,
        };
        info!("SyncSend:{}", session_id);
        Self {
            session_id,
            server_port,
            state: TcpState::SynSent,
            client_to_server: TcpReassembly::new(
                client_ip,
                client_port,
                server_ip,
                server_port,
                on_stream_packet,
            ),
            server_to_client: TcpReassembly::new(
                server_ip,
                server_port,
                client_ip,
                client_port,
                on_stream_packet,
            ),
        }
    }

    pub(crate) fn update(&mut self, origin: &TcpPacket<'_>) {
        let flags = origin.get_flags();
        match self.state {
            TcpState::SynSent if flags & TcpFlags::SYN != 0 && flags & TcpFlags::ACK != 0 => {
                self.state = TcpState::SynReceived;
                info!("SynReceived:{}", self.session_id);
            }

            TcpState::SynReceived if flags & TcpFlags::ACK != 0 && flags & TcpFlags::SYN == 0 => {
                self.state = TcpState::Established;
                info!("Established:{}", self.session_id);
            }

            TcpState::Established if flags & TcpFlags::FIN != 0 => {
                self.state = TcpState::FinWait;
                info!("FinWait:{}", self.session_id);
            }

            TcpState::FinWait if flags & TcpFlags::ACK != 0 => {
                self.state = TcpState::Closed;
                info!("Closed:{}", self.session_id);
            }

            _ => {}
        }
        let payload = origin.payload();
        let (dir, seq) = if origin.get_destination() == self.server_port {
            (&mut self.client_to_server, origin.get_sequence())
        } else {
            (&mut self.server_to_client, origin.get_sequence())
        };

        dir.on_packet(seq, flags, payload);
    }
}

#[derive(Hash, Eq, PartialEq, Clone, Debug)]
pub struct StreamKey {
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
}

impl fmt::Display for StreamKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f,"{}:{} -> {}:{}", self.src_ip, self.src_port, self.dst_ip, self.dst_port)
    }
}

pub struct TcpReassembly {
    pub stream_key: StreamKey,
    pub next_seq: Option<u32>,
    pub out_of_order: HashMap<u32, Vec<u8>>,
    pub on_stream_packet: OnStreamPacket,
}

impl TcpReassembly {
    pub fn new(
        src_ip: IpAddr,
        src_port: u16,
        dst_ip: IpAddr,
        dst_port: u16,
        on_stream_packet: OnStreamPacket,
    ) -> Self {
        Self {
            stream_key: StreamKey {
                src_ip,
                src_port,
                dst_ip,
                dst_port,
            },
            next_seq: None,
            out_of_order: HashMap::new(),
            on_stream_packet,
        }
    }
}

fn segment_len(flags: u8, payload: &[u8]) -> u32 {
    let mut len = payload.len() as u32;

    if flags & TcpFlags::SYN != 0 {
        len += 1;
    }
    if flags & TcpFlags::FIN != 0 {
        len += 1;
    }

    len
}

impl TcpReassembly {
    pub fn on_packet(&mut self, seq: u32, flags: u8, payload: &[u8]) {
        let seg_len = segment_len(flags, payload);
        if seg_len == 0 {
            return;
        }

        let next_seq = match self.next_seq {
            Some(n) => n,
            None => {
                self.accept(seq, payload, seg_len);
                return;
            }
        };

        if seq == next_seq {
            self.accept(seq, payload, seg_len);
        } else if seq > next_seq {
            self.out_of_order.insert(seq, payload.to_vec());
        }
    }

    fn accept(&mut self, seq: u32, payload: &[u8], seg_len: u32) {
        debug!("accept seq={} len={}", seq, seg_len);
        self.next_seq = Some(seq + seg_len);
        (self.on_stream_packet)(self.stream_key.clone(), payload);
        self.try_consume_queued();
    }

    fn try_consume_queued(&mut self) {
        let mut cur = self.next_seq.unwrap();

        while let Some(data) = self.out_of_order.remove(&cur) {
            cur += data.len() as u32;
            (self.on_stream_packet)(self.stream_key.clone(), &data);
            self.next_seq = Some(cur);
        }
    }
}
