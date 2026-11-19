//! In-process mock NATS broker for the federation tests. It implements the
//! subset of the protocol the async-nats client needs here: INFO, CONNECT,
//! PING/PONG, PUB, SUB and MSG. Not a conformant server: JetStream, headers,
//! NKEYs, queue groups, TLS and UNSUB are unimplemented, and most error paths
//! are ignored. If an async-nats upgrade breaks these tests, start here.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream, tcp::OwnedWriteHalf};
use tokio::sync::Mutex;

#[derive(Debug, Clone)]
pub struct Published {
    pub subject: String,
    pub payload: Vec<u8>,
}

type SubMap = Arc<Mutex<HashMap<String, (u64, Arc<Mutex<OwnedWriteHalf>>)>>>;

pub struct MockNats {
    addr: SocketAddr,
    published: Arc<Mutex<Vec<Published>>>,
    subs: SubMap,
    connects: Arc<Mutex<Vec<String>>>,
}

impl MockNats {
    pub async fn start() -> std::io::Result<Self> {
        Self::start_on("127.0.0.1:0").await
    }

    /// Start on a given address, e.g. to come up after a client tried it.
    pub async fn start_on(addr: &str) -> std::io::Result<Self> {
        let listener = TcpListener::bind(addr).await?;
        let addr = listener.local_addr()?;

        let published: Arc<Mutex<Vec<Published>>> = Arc::new(Mutex::new(Vec::new()));
        let subs: SubMap = Arc::new(Mutex::new(HashMap::new()));
        let connects: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));

        let pub_clone = Arc::clone(&published);
        let subs_clone = Arc::clone(&subs);
        let connects_clone = Arc::clone(&connects);

        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, _)) => {
                        let p = Arc::clone(&pub_clone);
                        let s = Arc::clone(&subs_clone);
                        let c = Arc::clone(&connects_clone);
                        tokio::spawn(async move {
                            let _ = handle_client(stream, p, s, c).await;
                        });
                    }
                    Err(_) => return,
                }
            }
        });

        Ok(Self {
            addr,
            published,
            subs,
            connects,
        })
    }

    pub fn url(&self) -> String {
        format!("nats://{}", self.addr)
    }

    pub async fn published(&self) -> Vec<Published> {
        self.published.lock().await.clone()
    }

    /// JSON option blocks of every CONNECT frame received so far.
    pub async fn connects(&self) -> Vec<String> {
        self.connects.lock().await.clone()
    }

    pub async fn wait_for_publishes(&self, count: usize, timeout: Duration) -> Vec<Published> {
        let deadline = Instant::now() + timeout;
        loop {
            let v = self.published().await;
            if v.len() >= count {
                return v;
            }
            if Instant::now() >= deadline {
                panic!("mock-nats: expected {count} publishes, got {}", v.len());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    pub async fn push(&self, subject: &str, payload: &[u8]) -> bool {
        let entry = self.subs.lock().await.get(subject).cloned();
        let Some((sid, writer)) = entry else {
            return false;
        };
        let header = format!("MSG {subject} {sid} {}\r\n", payload.len());
        let mut w = writer.lock().await;
        if w.write_all(header.as_bytes()).await.is_err() {
            return false;
        }
        if w.write_all(payload).await.is_err() {
            return false;
        }
        w.write_all(b"\r\n").await.is_ok()
    }
}

async fn handle_client(
    stream: TcpStream,
    published: Arc<Mutex<Vec<Published>>>,
    subs: SubMap,
    connects: Arc<Mutex<Vec<String>>>,
) -> std::io::Result<()> {
    let (reader, writer) = stream.into_split();
    let writer = Arc::new(Mutex::new(writer));

    {
        // The minimal INFO frame the async-nats client accepts.
        let info = "INFO {\"server_id\":\"mock\",\"version\":\"2.10.0\",\"go\":\"mock\",\"host\":\"127.0.0.1\",\"port\":0,\"max_payload\":1048576,\"client_id\":1,\"proto\":1,\"headers\":false}\r\n";
        writer.lock().await.write_all(info.as_bytes()).await?;
    }

    let mut reader = BufReader::new(reader);
    let mut line = String::new();
    loop {
        line.clear();
        let n = reader.read_line(&mut line).await?;
        if n == 0 {
            return Ok(());
        }
        let trimmed = line.trim_end_matches(['\r', '\n']);
        let mut parts = trimmed.splitn(2, ' ');
        let verb = parts.next().unwrap_or("").to_ascii_uppercase();
        let rest = parts.next().unwrap_or("");

        match verb.as_str() {
            "CONNECT" => connects.lock().await.push(rest.to_string()),
            "PING" => {
                writer.lock().await.write_all(b"PONG\r\n").await?;
            }
            "PONG" => {}
            "PUB" => {
                let tokens: Vec<&str> = rest.split_whitespace().collect();
                let (subject, n_bytes) = match tokens.as_slice() {
                    [subject, n] => (subject.to_string(), n.parse::<usize>().unwrap_or(0)),
                    [subject, _reply, n] => (subject.to_string(), n.parse::<usize>().unwrap_or(0)),
                    _ => continue,
                };
                let mut payload = vec![0u8; n_bytes];
                reader.read_exact(&mut payload).await?;
                let mut crlf = [0u8; 2];
                let _ = reader.read_exact(&mut crlf).await;
                published.lock().await.push(Published { subject, payload });
            }
            "SUB" => {
                let tokens: Vec<&str> = rest.split_whitespace().collect();
                let (subject, sid) = match tokens.as_slice() {
                    [subject, sid] => (subject.to_string(), sid.parse::<u64>().unwrap_or(0)),
                    [subject, _q, sid] => (subject.to_string(), sid.parse::<u64>().unwrap_or(0)),
                    _ => continue,
                };
                subs.lock()
                    .await
                    .insert(subject, (sid, Arc::clone(&writer)));
            }
            "UNSUB" => {}
            "" => {}
            _ => {}
        }
    }
}
