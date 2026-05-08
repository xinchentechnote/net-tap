use std::{collections::HashMap, net::IpAddr};

use pnet_packet::{
    Packet,
    tcp::{TcpFlags, TcpPacket},
};
use tracing::{error, info};

use crate::util;

pub struct TcpPacketWraper<'a> {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub origin: TcpPacket<'a>,
}

impl<'a> TcpPacketWraper<'a> {
    pub fn new(src_ip: IpAddr, dst_ip: IpAddr, tcp_packet: TcpPacket<'a>) -> Self {
        Self {
            src_ip: src_ip,
            dst_ip: dst_ip,
            origin: tcp_packet,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpState {
    SynSent,     // SYN
    SynReceived, // SYN + ACK
    Established, // ACK（三次握手完成）
    FinWait,     // FIN
    Closed,      // FIN + ACK
}

pub struct TcpSession {
    pub server_port: u16,
    pub session_id: TcpSessionKey,
    pub state: TcpState,
    client_to_server: TcpReassembly,
    server_to_client: TcpReassembly,
}

impl TcpSession {
    pub fn new(client_ip: IpAddr, client_port: u16, server_ip: IpAddr, server_port: u16) -> Self {
        let session_id = TcpSessionKey {
            client_ip,
            client_port,
            server_ip,
            server_port,
        };
        info!("SyncSend:{:?}", session_id);
        Self {
            server_port,
            session_id,
            state: TcpState::SynSent,
            client_to_server: TcpReassembly::default(),
            server_to_client: TcpReassembly::default(),
        }
    }

    pub(crate) fn update(&mut self, origin: &TcpPacket<'_>) {
        let flags = origin.get_flags();
        match self.state {
            TcpState::SynSent if flags & TcpFlags::SYN != 0 && flags & TcpFlags::ACK != 0 => {
                self.state = TcpState::SynReceived;
                info!("SynReceived:{:?}", self.session_id);
            }

            TcpState::SynReceived if flags & TcpFlags::ACK != 0 && flags & TcpFlags::SYN == 0 => {
                self.state = TcpState::Established;
                info!("Established:{:?}", self.session_id);
            }

            TcpState::Established if flags & TcpFlags::FIN != 0 => {
                self.state = TcpState::FinWait;
                info!("FinWait:{:?}", self.session_id);
            }

            TcpState::FinWait if flags & TcpFlags::ACK != 0 => {
                self.state = TcpState::Closed;
                info!("Closed:{:?}", self.session_id);
            }

            _ => {}
        }
        if origin.payload().len() > 0 {
            if self.state == TcpState::Established {
                if self.server_port == origin.get_destination() {
                    // to server
                    info!(
                        "To server {:?} \n{}",
                        self.session_id,
                        util::hex::to_hex_str_veiw(origin.payload())
                    );
                    self.client_to_server
                        .on_packet(origin.get_sequence(), origin.payload());
                } else {
                    // to client
                    info!(
                        "To client {:?} \n{}",
                        self.session_id,
                        util::hex::to_hex_str_veiw(origin.payload())
                    );
                    self.server_to_client
                        .on_packet(origin.get_sequence(), origin.payload());
                }
            } else {
                error!(
                    "{:?} is {:?} but rec payload\n",
                    self.session_id, self.state
                );
            }
        }
    }
}

#[derive(Default)]
pub struct TcpReassembly {
    /// 下一个期望的 seq
    pub next_seq: Option<u32>,

    /// 乱序缓存
    pub out_of_order: HashMap<u32, Vec<u8>>,
}

impl TcpReassembly {
    pub fn on_packet(&mut self, seq: u32, payload: &[u8]) {
        if payload.is_empty() {
            return;
        }

        let next_seq = match self.next_seq {
            Some(n) => n,
            None => {
                // 第一次数据
                self.accept_data(seq, payload);
                return;
            }
        };

        if seq == next_seq {
            // 正好接上
            self.accept_data(seq, payload);
        } else if seq > next_seq {
            // 乱序
            self.out_of_order.insert(seq, payload.to_vec());
        }
        // seq < next_seq → 重传或已处理，忽略
    }

    fn accept_data(&mut self, seq: u32, payload: &[u8]) {
        info!("handle data:{}", seq);
        self.next_seq = Some(seq + payload.len() as u32);
        self.try_consume_queued();
    }

    fn try_consume_queued(&mut self) {
        let mut cur = self.next_seq.unwrap();

        while let Some(data) = self.out_of_order.remove(&cur) {
            cur += data.len() as u32;
            info!("handle data:{}", cur);
            self.next_seq = Some(cur);
        }
    }
}
