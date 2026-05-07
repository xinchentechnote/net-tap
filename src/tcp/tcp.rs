
#[derive(Hash, Eq, PartialEq, Clone)]
pub struct TcpSessionKey {
    client_ip: IpAddr,
    server_ip: IpAddr,
    client_port: u16,
    server_port: u16,
}

struct TcpSession {
    client_to_server: TcpStream,
    server_to_client: TcpStream,
}

struct TcpStream {
    next_seq: Option<u32>,
    data: Vec<u8>,
    out_of_order: HashMap<u32, Vec<u8>>,
}