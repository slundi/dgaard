use std::{io, net::SocketAddr, sync::Arc};

use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;

/// Bind the `count` UDP sockets the workers listen on (at least one), all
/// sharing `addr` through SO_REUSEPORT, before any worker starts: a bind
/// failure (bad address, port taken, no privilege) aborts startup instead
/// of leaving a process that serves nothing.
///
/// The port must be free beforehand: SO_REUSEPORT would otherwise let a
/// second instance run by the same user share it silently and receive part
/// of the queries. With port 0, every socket shares the port picked for the
/// first one.
pub fn bind_listen_sockets(
    addr: &str,
    count: usize,
) -> Result<Vec<Arc<UdpSocket>>, Box<dyn std::error::Error>> {
    let addr: SocketAddr = addr.parse()?;
    ensure_port_free(addr)?;
    let first = bind_reuse_port(addr)?;
    let bound = first.local_addr()?;
    let mut sockets = vec![first];
    for _ in 1..count {
        sockets.push(bind_reuse_port(bound)?);
    }
    Ok(sockets)
}

/// Fail when another socket already holds `addr`. A plain bind (no
/// SO_REUSEADDR / SO_REUSEPORT) conflicts with any socket on the port;
/// it is released at once.
fn ensure_port_free(addr: SocketAddr) -> io::Result<()> {
    if addr.port() == 0 {
        return Ok(());
    }
    match std::net::UdpSocket::bind(addr) {
        Ok(_) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::AddrInUse => Err(io::Error::new(
            io::ErrorKind::AddrInUse,
            format!("{addr} is already in use (another dgaard instance?)"),
        )),
        Err(e) => Err(io::Error::new(e.kind(), format!("cannot bind {addr}: {e}"))),
    }
}

fn bind_reuse_port(addr: SocketAddr) -> io::Result<Arc<UdpSocket>> {
    // 1. Create a raw socket using socket2
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn binds_ipv4_ephemeral() {
        let sockets = bind_listen_sockets("127.0.0.1:0", 1).expect("ephemeral port");
        let addr = sockets[0].local_addr().unwrap();
        assert!(addr.port() > 0, "Ephemeral port should be non-zero");
        assert!(addr.ip().is_loopback());
    }

    #[tokio::test]
    async fn binds_ipv6_ephemeral() {
        let sockets = bind_listen_sockets("[::1]:0", 1).expect("ephemeral IPv6 port");
        assert!(sockets[0].local_addr().unwrap().port() > 0);
    }

    #[tokio::test]
    async fn rejects_invalid_address() {
        assert!(bind_listen_sockets("not-an-address", 1).is_err());
    }

    #[tokio::test]
    async fn one_socket_per_worker_all_on_the_same_port() {
        let sockets = bind_listen_sockets("127.0.0.1:0", 4).unwrap();
        assert_eq!(sockets.len(), 4);
        let port = sockets[0].local_addr().unwrap().port();
        assert!(
            sockets
                .iter()
                .all(|socket| socket.local_addr().unwrap().port() == port)
        );
        // Zero workers still get one socket.
        assert_eq!(bind_listen_sockets("127.0.0.1:0", 0).unwrap().len(), 1);
    }

    #[tokio::test]
    async fn port_held_by_another_process_is_refused() {
        // What a second instance meets: the first one's SO_REUSEPORT
        // sockets must not be joined.
        let first = bind_listen_sockets("127.0.0.1:0", 2).unwrap();
        let taken = first[0].local_addr().unwrap().to_string();
        let err = bind_listen_sockets(&taken, 2).unwrap_err();
        assert!(err.to_string().contains("already in use"), "{err}");

        // A plain socket holding the port is refused just the same.
        let plain = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let held = plain.local_addr().unwrap().to_string();
        assert!(bind_listen_sockets(&held, 1).is_err());
    }

    #[tokio::test]
    async fn free_fixed_port_is_bound() {
        // Find a free port, release it, then bind it for real.
        let port = std::net::UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let addr = format!("127.0.0.1:{port}");
        match bind_listen_sockets(&addr, 2) {
            Ok(sockets) => assert_eq!(sockets[1].local_addr().unwrap().port(), port),
            // Another test grabbed it in between: not what this test checks.
            Err(e) => assert!(e.to_string().contains("already in use"), "{e}"),
        }
    }

    #[test]
    fn privileged_port_error_names_the_address() {
        // Only meaningful without CAP_NET_BIND_SERVICE; skipped as root.
        let err = match ensure_port_free("127.0.0.1:1".parse().unwrap()) {
            Ok(()) => return,
            Err(e) => e,
        };
        assert!(err.to_string().contains("127.0.0.1:1"), "{err}");
    }
}
