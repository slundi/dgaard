use std::{net::SocketAddr, sync::Arc};

use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;

pub fn get_socket(addr: &str) -> Result<Arc<tokio::net::UdpSocket>, Box<dyn std::error::Error>> {
    // 1. Create a raw socket using socket2
    let addr: SocketAddr = addr.parse()?;
    let socket = Socket::new(Domain::for_address(addr), Type::DGRAM, Some(Protocol::UDP))?;

    // 2. Enable SO_REUSEPORT (and SO_REUSEADDR for good measure)
    // Note: .set_reuse_port() is available on Unix systems.
    #[cfg(all(unix, not(target_os = "solaris"), not(target_os = "illumos")))]
    socket.set_reuse_port(true)?;
    socket.set_reuse_address(true)?;

    socket.set_nonblocking(true)?; // for tokio compatibility

    // 1. Bind the UDP socket
    socket.bind(&addr.into())?;

    // 4. Convert to Tokio's UdpSocket
    let std_socket: std::net::UdpSocket = socket.into();
    let tokio_socket = Arc::new(UdpSocket::from_std(std_socket)?);
    Ok(tokio_socket)
}

pub fn count_dots(domain: &str) -> u8 {
    domain.bytes().filter(|&b| b == b'.').count() as u8
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_count_dots() {
        assert_eq!(count_dots("tld"), 0);
        assert_eq!(count_dots("example.org"), 1);
        assert_eq!(count_dots("with.sub.domains.end"), 3);
    }
}
