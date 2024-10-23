use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use crate::file_utils;

#[allow(dead_code)]
pub struct Handshake {
    pub plen: u8,
    pub protocol: &'static[u8],
    pub reserved: [u8; 8],
    pub infohash: Vec<u8>,
    pub client_id: Vec<u8>,
}

#[allow(dead_code)]
impl Handshake {
    pub fn new(info_hash: String, client: String) -> Handshake {
        let protocol: &[u8] = "BitTorrent protocol".as_bytes();
        let plen = protocol.len() as u8;
        let infohash = hex::decode(info_hash.as_bytes())
            .expect("Invalid hash received in Handshake");
        let client_id = client.into_bytes();

        Handshake {
            plen,
            protocol,
            reserved: [0u8; 8],
            infohash,
            client_id,
        }
    }

    pub fn get(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(self.plen);
        bytes.extend_from_slice(self.protocol);
        bytes.extend_from_slice(&self.reserved);
        bytes.extend_from_slice(&self.infohash);
        bytes.extend_from_slice(&self.client_id);

        bytes
    }
}


pub async fn send_message(message_type: &str, stream: &mut TcpStream, piece_index: &u32, block_offset: u32, block_length: u32) -> Result<(), Box<dyn std::error::Error>> {
    let mut request_message = Vec::new();
    match message_type {
        "request" => {
            request_message.extend_from_slice(&(13u32.to_be_bytes()));
            request_message.push(6);
            request_message.extend_from_slice(&piece_index.to_be_bytes());
            request_message.extend_from_slice(&block_offset.to_be_bytes());
            request_message.extend_from_slice(&block_length.to_be_bytes());
            stream.write_all(&request_message).await?;
            Ok(())
        }
        "interested" => {
            request_message.extend_from_slice(&(1u32.to_be_bytes()));
            request_message.push(2);
            stream.write_all(&request_message).await?;
            Ok(())
        }
        _ => {
            return Err("No message type provided to function".into());
        }

    }
}

#[allow(dead_code)]
#[derive(Clone, Copy)]
pub struct DownloadContext {
    pub piece_length: u32,
    pub max_requests: usize,
}

#[allow(dead_code)]
impl DownloadContext {
    pub fn new(piece_length: u32, max_requests: usize) -> DownloadContext {
        DownloadContext {
            piece_length,
            max_requests,
        }
    }

   
    pub async fn download_piece(&mut self, stream: &mut TcpStream, piece_index: &u32) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut block_offset = 0;
        let mut pending_requests = 0;
        let mut blocks = Vec::new();
        let mut block_size = 16 * 1024;
        let mut block_index = 0;

        while block_offset < self.piece_length {
            if block_offset < self.piece_length && pending_requests < self.max_requests {
                println!("Sending request for block {}", block_index);
                send_message("request", stream, piece_index, block_offset, block_size).await?;
                block_offset += block_size;
                pending_requests += 1;
                block_index += 1;
                block_size = file_utils::calc_block_size(self.piece_length, block_size, block_index);
            }

            if let Some((_, received_block_offset, block_data)) = 
                receive_response(stream).await? {
                    println!("Received block data");
                    blocks.push((received_block_offset, block_data));
                    pending_requests -= 1;
            }
        }
        Ok(file_utils::join_blocks(blocks, self.piece_length))
    }
}

pub async fn receive_response(stream: &mut TcpStream) -> Result<Option<(u32, u32, Vec<u8>)>, Box<dyn std::error::Error>> {
    let mut length_prefix = [0u8; 4];
    stream.read_exact(&mut length_prefix).await?;
    let length = u32::from_be_bytes(length_prefix);
    
    if length == 0 {
        return Ok(None);
    }

    let mut message_id = [0u8; 1];
    stream.read_exact(&mut message_id).await?;

    match message_id[0] {
        7 => {
            let mut piece_index_bytes = [0u8; 4];
            let mut block_offset_bytes = [0u8; 4];
            stream.read_exact(&mut piece_index_bytes).await?;
            stream.read_exact(&mut block_offset_bytes).await?;
            
            let piece_index = u32::from_be_bytes(piece_index_bytes);
            let block_offset = u32::from_be_bytes(block_offset_bytes);
            let block_length = length - 9;
            
            let mut block_data = vec![0u8; block_length as usize];
            stream.read_exact(&mut block_data).await?;
            
            Ok(Some((piece_index, block_offset, block_data)))
        }
        1 => { // unchoke
            println!("Received unchoke message");
            Ok(None)
        }
        5 => { // bitfield
            let bitfield_length = length - 1;
            let mut bitfield = vec![0u8; bitfield_length as usize];
            stream.read_exact(&mut bitfield).await?;
            println!("Received bitfield message");
            Ok(None)
        }
        _ => {
            // Handle other message types
            let mut other_data = vec![0u8; (length - 1) as usize];
            stream.read_exact(&mut other_data).await?;
            println!("Received message type: {}", message_id[0]);
            Ok(None)
        }
    }
}