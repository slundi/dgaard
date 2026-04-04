use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

use crate::{CONFIG, config::Config, dns::handle_query};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::{net::UdpSocket, runtime::Builder};

use crate::GLOBAL_SEED;

fn get_socket(addr: &str) -> Result<Arc<tokio::net::UdpSocket>, Box<dyn std::error::Error>> {
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

pub(crate) fn start_with_single_worker() -> Result<(), Box<dyn std::error::Error>> {
    let runtime = Builder::new_current_thread()
        .enable_all()
        .thread_stack_size(CONFIG.load().server.runtime.stack_size)
        .max_blocking_threads(CONFIG.load().server.runtime.max_blocking_threads)
        .build()?;
    runtime.block_on(async {
        let tokio_socket = get_socket(&CONFIG.load().server.listen_addr)?;
        // 2. Buffer for incoming DNS packets (DNS over UDP is typically 512 bytes,
        // but can be larger with EDNS0, so 4096 is a safe buffer size).
        let mut buf = [0u8; 4096];
        loop {
            match tokio_socket.recv_from(&mut buf).await {
                Ok((len, addr)) => {
                    let packet = buf[..len].to_vec();
                    let socket_inner = Arc::clone(&tokio_socket);

                    // 3. Spawn a task for each request to keep the proxy non-blocking
                    tokio::spawn(async move {
                        if let Err(e) = handle_query(socket_inner, packet, addr).await {
                            eprintln!("Error handling query from {}: {}", addr, e);
                        }
                    });
                }
                Err(e) => {
                    eprintln!("Error receiving packet: {}", e);
                }
            }
        }
    })
}

pub(crate) fn start_with_workers(
    cpus: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let runtime = Builder::new_multi_thread()
        .enable_all()
        .worker_threads(cpus)
        .thread_name_fn(|| {
            static ATOMIC_ID: AtomicUsize = AtomicUsize::new(0);
            let id = ATOMIC_ID.fetch_add(1, Ordering::SeqCst);
            format!("dgaard-{}", id)
        })
        .thread_stack_size(CONFIG.load().server.runtime.stack_size)
        .max_blocking_threads(CONFIG.load().server.runtime.max_blocking_threads)
        .build()?;

    runtime.block_on(async {
        let mut futures = Vec::new();
        for _ in 0..cpus {
            // let cfg = config.clone();
            futures.push(tokio::spawn(async move {
                let addr = &CONFIG.load().server.listen_addr;
                let tokio_socket =
                    get_socket(addr).expect("Failed to bind socket");
                let mut buf = [0u8; 4096];
                loop {
                    match tokio_socket.recv_from(&mut buf).await {
                        Ok((len, addr)) => {
                            let packet = buf[..len].to_vec();
                            let socket_inner = Arc::clone(&tokio_socket);

                            // 3. Spawn a task for each request to keep the proxy non-blocking
                            tokio::spawn(async move {
                                if let Err(e) = handle_query(socket_inner, packet, addr).await {
                                    eprintln!("Error handling query from {}: {}", addr, e);
                                }
                            });
                        }
                        Err(e) => {
                            eprintln!("Error receiving packet: {}", e);
                        }
                    }
                }
            }));
        }
        for h in futures {
            let _ = h.await;
        }
        Ok(())
    })
}

pub(crate) fn init_global_seed() {
    match getrandom::u64() {
        Ok(seed) => GLOBAL_SEED.store(seed, Ordering::Relaxed),
        Err(e) => {
            eprintln!("Unable to have a random seed: {}", e);
            GLOBAL_SEED.store(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("time should go forward")
                    .as_secs(),
                Ordering::Relaxed,
            );
        }
    }
}
