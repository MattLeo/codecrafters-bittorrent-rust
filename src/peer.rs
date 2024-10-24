use serde::{Deserialize, Serialize};
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, net::TcpStream, sync::Mutex};
use core::str;
use std::{collections::{VecDeque,HashMap}, sync::Arc, time::Duration, future::Future, pin::Pin};
use crate::{torrent::Torrent, transceive};

#[allow(dead_code)]
#[derive(Debug, Serialize, Deserialize)]
pub struct PeerData {
    pub ip: String,
    pub port: u16,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct PeerConnection {
    pub stream: Arc<Mutex<TcpStream>>,
    pub peer_id: String,
    pub ip: String,
    pub port: u16,
    pub is_choked: bool,
    pub available: bool,
    pub last_used: std::time::Instant,
    pub failed_requests: u32,
    pub extensions: Option<HashMap<String, u32>>,
}

#[allow(dead_code)]
pub struct PeerPool {
    connections: Arc<Mutex<VecDeque<PeerConnection>>>,
    max_connections: usize,
    connection_timeout: Duration,
    max_failed_requests: u32,
}

impl PeerPool {
    pub fn new(max_connections: usize) -> Self {
        Self {
            connections: Arc::new(Mutex::new(VecDeque::new())),
            max_connections,
            connection_timeout: Duration::from_secs(30),
            max_failed_requests: 3,
        }
    }

    pub async fn add_peer(&self, peer: &PeerData, torrent: &Torrent) -> Result<(), Box<dyn std::error::Error>> {
        let mut connections = self.connections.lock().await;
        
        if connections.iter().any(|conn| conn.ip == peer.ip && conn.port == peer.port) {
            return Ok(());
        }
        
        if connections.len() >= self.max_connections {
            self.cleanup_dead_connections(&mut connections).await;

            if connections.len() >= self.max_connections {
                return Ok(());
            }
        }

        match setup_peer_connection(peer, torrent).await {
            Ok((stream, peer_id)) => {
                println!("Successfully added peer {}:{}", peer.ip, peer.port); // Debug
                connections.push_back(PeerConnection {
                    stream: Arc::new(Mutex::new(stream)),
                    peer_id,
                    ip: peer.ip.clone(),
                    port: peer.port,
                    is_choked: false,
                    available: true,
                    last_used: std::time::Instant::now(),
                    failed_requests: 0,
                    extensions: None,
                });
                Ok(())
            },
            Err(e) => {
                eprintln!("Failed to establish connection with peer {}:{} - {}", peer.ip, peer.port, e);
                Err(e)
            }
        }
    }

    pub async fn get_connection(&self) -> Option<PeerConnection> {
        let mut connections = self.connections.lock().await;
        
        for i in 0..connections.len() {
            if let Some(conn) = connections.get_mut(i) {
                if conn.available && !conn.is_choked && conn.failed_requests < self.max_failed_requests {
                    conn.available = false;
                    conn.last_used = std::time::Instant::now();
                    return Some(conn.clone());
                }
            }
        }
        None
    }

    pub async fn return_connection(&self, peer_id: &str, success: bool) {
        let mut connections = self.connections.lock().await;
        if let Some(conn) = connections.iter_mut().find(|c| c.peer_id == peer_id) {
            conn.available = true;
            if !success {
                conn.failed_requests += 1;
            } else {
                conn.failed_requests = 0;
            }
        }
    }

    pub async fn mark_connections_choked(&self, peer_id: &str, is_choked: bool) {
        let mut connections = self.connections.lock().await;
        if let Some(conn) = connections.iter_mut().find(|c| c.peer_id == peer_id) {
            conn.is_choked = is_choked;
        }
    }

    pub async fn remove_connections(&self, peer_id: &str) {
        let mut connections = self.connections.lock().await;
        connections.retain(|conn| conn.peer_id != peer_id);
    }

    pub async fn active_connections(&self)-> usize {
        let connections = self.connections.lock().await;
        connections.iter().filter(|conn| !conn.available).count()
    }

    async fn cleanup_dead_connections(&self, connections: &mut VecDeque<PeerConnection>) {
        let now = std::time::Instant::now();
        connections.retain(|conn| {
            let alive = now.duration_since(conn.last_used) < self.connection_timeout
                && conn.failed_requests < self.max_failed_requests;
            if !alive {
                eprintln!("Removing dead connection to peer {}:{}", conn.ip, conn.port);
            }
            alive
        });
    }

    pub async fn health_check(&self) -> usize {
        let mut connections = self.connections.lock().await;
        let initial_count = connections.len();
        self.cleanup_dead_connections(&mut connections).await;
        initial_count - connections.len()
    }
}

async fn setup_peer_connection(peer: &PeerData, torrent: &Torrent) -> Result<(TcpStream, String), Box<dyn std::error::Error>> {
    let client_id = "TestRTAAA11234567899".to_string();
    let handshake = transceive::Handshake::new(torrent.info_hash()?, client_id.clone());

    println!("Attempting to connect to peer {}:{}", peer.ip, peer.port); // Debug

    let stream = tokio::time::timeout(
        Duration::from_secs(10),
        TcpStream::connect(format!("{}:{}", peer.ip, peer.port))
    ).await??;

    println!("Connected to peer {}:{}", peer.ip, peer.port); // Debug

    stream.set_nodelay(true)?;
    
    let mut stream = stream;
    stream.write_all(&handshake.get()).await?;

    let mut handshake_response = [0u8; 68];
    stream.read_exact(&mut handshake_response).await?;

    let peer_id = hex::encode(&handshake_response[48..]);

    println!("Received handshake response from peer {}", peer_id); 

    let _bitfield = receive_message(&mut stream).await?;
    send_interested(&mut stream).await?;
    let _unchoke = receive_message(&mut stream).await?;

    Ok((stream, peer_id))
}

async fn receive_message(stream: &mut TcpStream) -> Result<(), Box<dyn std::error::Error>> {
    let mut length_prefix = [0u8; 4];
    stream.read_exact(&mut length_prefix).await?;

    let length = u32::from_be_bytes(length_prefix);
    if length > 0 {
        let mut message = vec![0u8; length as usize];
        stream.read_exact(&mut message).await?;
    }

    Ok(())
}

async fn send_interested(stream: &mut TcpStream) -> Result<(), Box<dyn std::error::Error>> {
    let interested_message = [0x00, 0x00, 0x00, 0x01, 0x02];
    stream.write_all(&interested_message).await?;
    Ok(())
}

pub async fn with_stream<F>(
    conn: &PeerConnection,
    f: F,
) -> Result<Vec<u8>, Box<dyn std::error::Error>>
where
    F: FnOnce(&mut TcpStream) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, Box<dyn std::error::Error>>>>>,
{
    let mut stream = conn.stream.lock().await;
    f(&mut *stream).await
}
