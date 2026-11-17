//! DNS over TCP (RFC 1035 §4.2.2, RFC 7766).
//!
//! Every message is prefixed by its length on two bytes. The listener
//! serves pipelined queries on one connection, in order, under an idle
//! timeout, a per-message read timeout and a cap on open connections; the
//! client side is used for TCP fallback when a UDP answer comes back
//! truncated (TC=1).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, watch};
use tokio::time::timeout;

use crate::dns::packet::Transport;

/// Read one length-prefixed message. `Ok(None)` when the peer closed the
/// connection cleanly before a new message (end of a session).
pub(crate) async fn read_message<R: AsyncRead + Unpin>(
    stream: &mut R,
) -> std::io::Result<Option<Vec<u8>>> {
    let mut length = [0u8; 2];
    match stream.read_exact(&mut length).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let mut message = vec![0u8; usize::from(u16::from_be_bytes(length))];
    stream.read_exact(&mut message).await?;
    Ok(Some(message))
}

/// Write one length-prefixed message (at most 65 535 bytes).
pub(crate) async fn write_message<W: AsyncWrite + Unpin>(
    stream: &mut W,
    message: &[u8],
) -> std::io::Result<()> {
    let length = u16::try_from(message.len()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "DNS message over 65535 bytes",
        )
    })?;
    let mut framed = Vec::with_capacity(message.len() + 2);
    framed.extend_from_slice(&length.to_be_bytes());
    framed.extend_from_slice(message);
    stream.write_all(&framed).await?;
    stream.flush().await
}

/// One query/response exchange with `server` over a fresh TCP connection,
/// bounded by `deadline` as a whole.
pub(crate) async fn exchange(
    server: SocketAddr,
    query: &[u8],
    deadline: Duration,
) -> std::io::Result<Vec<u8>> {
    let attempt = async {
        let mut stream = TcpStream::connect(server).await?;
        write_message(&mut stream, query).await?;
        read_message(&mut stream).await?.ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "TCP closed before the answer",
            )
        })
    };
    timeout(deadline, attempt)
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "DNS over TCP timeout"))?
}

/// Limits of the TCP listener.
#[derive(Debug, Clone, Copy)]
pub(crate) struct TcpLimits {
    /// Open connections at most; further ones are closed at once.
    pub max_connections: usize,
    /// How long a connection may wait for its next query (RFC 7766 §6.2.3).
    pub idle_timeout: Duration,
    /// How long one query may take to arrive once its length is read.
    pub read_timeout: Duration,
}

impl Default for TcpLimits {
    fn default() -> Self {
        Self {
            max_connections: 128,
            idle_timeout: Duration::from_secs(10),
            read_timeout: Duration::from_secs(5),
        }
    }
}

/// Accept DNS-over-TCP connections until `shutdown` flips to `true`.
///
/// `allowed` is the same client ACL as UDP. `query_permits` is the global
/// query semaphore shared with UDP: a query arriving while it is exhausted
/// gets the same minimal SERVFAIL.
pub(crate) async fn serve(
    listener: TcpListener,
    limits: TcpLimits,
    allowed: Arc<dyn Fn(std::net::IpAddr) -> bool + Send + Sync>,
    query_permits: Arc<Semaphore>,
    mut shutdown: watch::Receiver<bool>,
) {
    let connections = Arc::new(Semaphore::new(limits.max_connections));
    loop {
        tokio::select! {
            biased;
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    return;
                }
            }
            accepted = listener.accept() => {
                let Ok((stream, peer)) = accepted else {
                    continue;
                };
                if !allowed(peer.ip()) {
                    continue; // dropping the stream closes it
                }
                let Ok(slot) = Arc::clone(&connections).try_acquire_owned() else {
                    continue; // at capacity: close rather than queue
                };
                let permits = Arc::clone(&query_permits);
                tokio::spawn(async move {
                    let _slot = slot;
                    serve_connection(stream, peer, limits, permits).await;
                });
            }
        }
    }
}

/// Answer the queries of one connection in order until the client closes
/// it, goes idle, sends a malformed frame or a write fails.
async fn serve_connection(
    mut stream: TcpStream,
    peer: SocketAddr,
    limits: TcpLimits,
    permits: Arc<Semaphore>,
) {
    loop {
        let mut length = [0u8; 2];
        match timeout(limits.idle_timeout, stream.read_exact(&mut length)).await {
            Ok(Ok(_)) => {}
            // Idle timeout, clean close or reset.
            Ok(Err(_)) | Err(_) => return,
        }
        let mut query = vec![0u8; usize::from(u16::from_be_bytes(length))];
        if query.is_empty() {
            return;
        }
        match timeout(limits.read_timeout, stream.read_exact(&mut query)).await {
            Ok(Ok(_)) => {}
            Ok(Err(_)) | Err(_) => return,
        }

        let response = match Arc::clone(&permits).try_acquire_owned() {
            Ok(_permit) => crate::dns::answer_query(&query, peer, Transport::Tcp).await,
            Err(_) => crate::runtime::build_minimal_servfail(&query),
        };
        if let Some(response) = response {
            let written = timeout(limits.read_timeout, write_message(&mut stream, &response)).await;
            if !matches!(written, Ok(Ok(()))) {
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use hickory_resolver::proto::op::{Message, OpCode, Query, ResponseCode};
    use hickory_resolver::proto::rr::{Name, RecordType};

    use super::*;

    /// A NOTIFY with `id`: answered NOTIMP by the screening step alone, so
    /// listener tests do not depend on the filter pipeline or upstream.
    fn notify(id: u16) -> Vec<u8> {
        let mut msg = Message::query();
        msg.metadata.id = id;
        msg.metadata.op_code = OpCode::Notify;
        msg.add_query(Query::query(
            Name::from_ascii("example.com.").unwrap(),
            RecordType::SOA,
        ));
        msg.to_vec().unwrap()
    }

    fn limits() -> TcpLimits {
        TcpLimits {
            max_connections: 4,
            idle_timeout: Duration::from_millis(300),
            read_timeout: Duration::from_millis(300),
        }
    }

    /// Start a listener on 127.0.0.1; returns its address and the shutdown
    /// switch.
    async fn start(
        limits: TcpLimits,
        allowed: bool,
        permits: usize,
    ) -> (SocketAddr, watch::Sender<bool>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        tokio::spawn(serve(
            listener,
            limits,
            Arc::new(move |_| allowed),
            Arc::new(Semaphore::new(permits)),
            shutdown_rx,
        ));
        (addr, shutdown_tx)
    }

    async fn read_reply(stream: &mut TcpStream) -> Option<Message> {
        let message = timeout(Duration::from_secs(2), read_message(stream))
            .await
            .expect("no reply within 2 s")
            .ok()??;
        Some(Message::from_vec(&message).unwrap())
    }

    /// True when the server closed the connection (EOF or reset).
    async fn closed(stream: &mut TcpStream) -> bool {
        let mut byte = [0u8; 1];
        matches!(
            timeout(Duration::from_secs(2), stream.read(&mut byte)).await,
            Ok(Ok(0)) | Ok(Err(_))
        )
    }

    // ---- framing ----

    #[tokio::test]
    async fn framing_round_trips_and_detects_clean_close() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        write_message(&mut client, b"hello").await.unwrap();
        write_message(&mut client, b"").await.unwrap();
        drop(client);
        assert_eq!(read_message(&mut server).await.unwrap().unwrap(), b"hello");
        assert_eq!(read_message(&mut server).await.unwrap().unwrap(), b"");
        assert!(
            read_message(&mut server).await.unwrap().is_none(),
            "clean EOF"
        );
    }

    #[tokio::test]
    async fn framing_rejects_a_truncated_message_and_oversized_writes() {
        let (mut client, mut server) = tokio::io::duplex(1024);
        client.write_all(&[0x00, 0x10, 1, 2, 3]).await.unwrap();
        drop(client);
        assert!(read_message(&mut server).await.is_err());

        let (mut sink, _keep) = tokio::io::duplex(16);
        assert!(write_message(&mut sink, &vec![0u8; 70_000]).await.is_err());
    }

    #[tokio::test]
    async fn exchange_talks_to_a_tcp_server_and_times_out() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let query = read_message(&mut stream).await.unwrap().unwrap();
            write_message(&mut stream, &[query, b"!".to_vec()].concat())
                .await
                .unwrap();
        });
        let answer = exchange(addr, b"ping", Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(answer, b"ping!");

        // A server that accepts but never answers.
        let silent = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let silent_addr = silent.local_addr().unwrap();
        tokio::spawn(async move {
            let _held = silent.accept().await;
            tokio::time::sleep(Duration::from_secs(5)).await;
        });
        let err = exchange(silent_addr, b"ping", Duration::from_millis(100))
            .await
            .unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
    }

    // ---- listener ----

    #[tokio::test]
    async fn pipelined_queries_are_answered_in_order() {
        let (addr, _shutdown) = start(limits(), true, 8).await;
        let mut stream = TcpStream::connect(addr).await.unwrap();
        // Three queries in a single write (RFC 7766 §6.2.1.1 pipelining).
        let mut burst = Vec::new();
        for id in [1u16, 2, 3] {
            let query = notify(id);
            burst.extend_from_slice(&(query.len() as u16).to_be_bytes());
            burst.extend_from_slice(&query);
        }
        stream.write_all(&burst).await.unwrap();
        for id in [1u16, 2, 3] {
            let reply = read_reply(&mut stream).await.expect("reply");
            assert_eq!(reply.metadata.id, id);
            assert_eq!(reply.metadata.response_code, ResponseCode::NotImp);
        }
    }

    #[tokio::test]
    async fn idle_connections_are_closed() {
        let (addr, _shutdown) = start(limits(), true, 8).await;
        let mut stream = TcpStream::connect(addr).await.unwrap();
        let started = std::time::Instant::now();
        assert!(closed(&mut stream).await);
        assert!(started.elapsed() >= Duration::from_millis(250));
    }

    #[tokio::test]
    async fn half_sent_query_is_dropped_after_the_read_timeout() {
        let (addr, _shutdown) = start(limits(), true, 8).await;
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream.write_all(&[0x00, 0x40, 0x12]).await.unwrap(); // 64 announced, 1 sent
        assert!(closed(&mut stream).await);
    }

    #[tokio::test]
    async fn denied_clients_are_closed_without_an_answer() {
        let (addr, _shutdown) = start(limits(), false, 8).await;
        let mut stream = TcpStream::connect(addr).await.unwrap();
        let _ = write_message(&mut stream, &notify(1)).await;
        assert!(closed(&mut stream).await);
    }

    #[tokio::test]
    async fn connections_over_the_cap_are_closed() {
        let capped = TcpLimits {
            max_connections: 1,
            idle_timeout: Duration::from_secs(5),
            ..limits()
        };
        let (addr, _shutdown) = start(capped, true, 8).await;
        let mut first = TcpStream::connect(addr).await.unwrap();
        write_message(&mut first, &notify(1)).await.unwrap();
        assert!(
            read_reply(&mut first).await.is_some(),
            "first connection served"
        );

        let mut second = TcpStream::connect(addr).await.unwrap();
        assert!(closed(&mut second).await, "second connection refused");

        // The first one keeps working.
        write_message(&mut first, &notify(2)).await.unwrap();
        assert_eq!(read_reply(&mut first).await.unwrap().metadata.id, 2);
    }

    #[tokio::test]
    async fn exhausted_query_permits_get_servfail() {
        let (addr, _shutdown) = start(limits(), true, 0).await;
        let mut stream = TcpStream::connect(addr).await.unwrap();
        write_message(&mut stream, &notify(9)).await.unwrap();
        let reply = read_reply(&mut stream).await.unwrap();
        assert_eq!(reply.metadata.id, 9);
        assert_eq!(reply.metadata.response_code, ResponseCode::ServFail);
    }

    #[tokio::test]
    async fn listener_stops_accepting_on_shutdown() {
        let (addr, shutdown) = start(limits(), true, 8).await;
        shutdown.send(true).unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(TcpStream::connect(addr).await.is_err(), "listener closed");
    }
}
