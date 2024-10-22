use std::{io::{Read, Write}, net::TcpStream};

use crate::{file_utils, torrent, tracker};

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


pub fn send_message(message_type: &str, stream: &mut TcpStream, piece_index: &u32, block_offset: u32, block_length: u32) -> Result<(), Box<dyn std::error::Error>> {
    let mut request_message = Vec::new();
    match message_type {
        "request" => {
            request_message.extend_from_slice(&(13u32.to_be_bytes()));
            request_message.push(6);
            request_message.extend_from_slice(&piece_index.to_be_bytes());
            request_message.extend_from_slice(&block_offset.to_be_bytes());
            request_message.extend_from_slice(&block_length.to_be_bytes());
            stream.write_all(&request_message)?;
            Ok(())
        }
        "interested" => {
            request_message.extend_from_slice(&(1u32.to_be_bytes()));
            request_message.push(2);
            stream.write_all(&request_message)?;
            Ok(())
        }
        _ => {
            return Err("No message type provided to function".into());
        }

    }
}

#[allow(dead_code)]
pub struct DownloadContext {
    pub stream: TcpStream,
    pub piece_length: u32,
    pub max_requests: usize,
}

#[allow(dead_code)]
impl DownloadContext {
    pub fn new(stream: TcpStream, piece_length: u32, max_requests: usize) -> DownloadContext {
        DownloadContext {
            stream,
            piece_length,
            max_requests,
        }
    }

    pub fn download_piece(&mut self, piece_index: &u32) -> Result<Vec<u8>,Box<dyn std::error::Error>> {
        let mut block_offset = 0;
        let mut pending_requests = 0;
        let mut blocks = Vec::new();
        let mut block_size = 16 * 1024;
        let mut block_index = 0;

        while block_offset < self.piece_length {
            if block_offset < self.piece_length && pending_requests < self.max_requests {
                println!("Sending request for block {}", block_index);
                send_message("request", &mut self.stream, &piece_index, block_offset, block_size)?;
                block_offset += block_size;
                pending_requests += 1;
                block_index += 1;
                block_size = file_utils::calc_block_size(self.piece_length, block_size, block_index);
            }

            if let Some((_, received_block_offset, block_data)) = 
                recieve_response(&mut self.stream)? {
                    println!("Received block data");
                    blocks.push((received_block_offset, block_data));
                    pending_requests -= 1;
            }
        }
        Ok(file_utils::join_blocks(blocks, self.piece_length))
    }


}

pub fn setup_connection(torrent: &torrent::Torrent) -> Result<(TcpStream, tracker::TrackerResponse), Box<dyn std::error::Error>> {
    let info_hash = torrent.info_hash()?;
    let client_id = "TestRTAAA11234567899".to_string();
    let request = tracker::TrackerRequest::new(torrent.announce.clone(), info_hash.clone(), torrent.info.length);
    let response = request.get_response().unwrap();
    let tracker_info = tracker::TrackerResponse::new(&*response)?;

    let handshake = Handshake::new(info_hash, client_id);
    let mut handshake_response = [0u8; 68];
    let peer = &tracker_info.peers[0];

    let mut stream = TcpStream::connect(format!("{}:{}", peer.ip, peer.port))?;
    stream.write_all(&handshake.get())?;
    stream.read_exact(&mut handshake_response)?;

    let _bitfield = recieve_response(&mut stream)?;
    send_message("interested", &mut stream, &0, 0, 0)?;
    let _unchoke = recieve_response(&mut stream)?;

    Ok((stream, tracker_info))
}

pub fn recieve_response(stream: &mut TcpStream) -> Result<Option<(u32, u32, Vec<u8>)>, Box<dyn std::error::Error>> {
    let mut length_prefix = [0u8; 4];
    let bytes_read = stream.read_exact(&mut length_prefix);
    if let Err(e) = bytes_read {
        println!("length prefix is error {:?}", e);
        return Ok(None);
    }
    let length = u32::from_be_bytes(length_prefix);
    println!("Length prefix received: {}", length);
    if length == 0 {
        println!("length is 0");
        return Ok(None);
    }

    let mut message_id = [0u8; 1];
   read_exact_with_retry(stream,&mut message_id)?;
   println!("Message ID received: {}", message_id[0]);
    if message_id[0] == 7 {
        println!("block message received");
        let mut piece_index_bytes = [0u8; 4];
        let mut block_offset_bytes = [0u8; 4];
        read_exact_with_retry(stream, &mut piece_index_bytes)?;
        read_exact_with_retry(stream, &mut block_offset_bytes)?;
        let piece_index = u32::from_be_bytes(piece_index_bytes);
        let block_offset = u32::from_be_bytes(block_offset_bytes);
        let block_length = length - 9;
        let mut block_data = vec![0u8; block_length as usize];
        read_exact_with_retry(stream, &mut block_data)?;
        println!("Block data successfully read, size: {}", block_data.len());
        
        Ok(Some((piece_index, block_offset, block_data)))
    } else if message_id[0] == 1 {
        println!("unchoke received");
        Ok(None)
    } else if message_id[0] ==  5 {
        let bitfield_length = length - 1;
        let mut bitfield = vec![0u8; bitfield_length as usize];
        read_exact_with_retry(stream, &mut bitfield)?;
        println!("bitfield received");
        Ok(None)
    } else if message_id[0] == 8 {
        println!("cancel received");
        Ok(None)
    } else if message_id[0] == 0 {
        println!("choke received");
        Ok(None)
    } else {
        println!("other message is received");
        let mut other_buffer = vec![0u8; (length -1) as usize];
        read_exact_with_retry(stream, &mut other_buffer)?;
        Ok(None)
    }
}

fn read_exact_with_retry(stream: &mut TcpStream, buf: &mut [u8]) -> std::io::Result<()> {
    let mut total_read = 0;
    let mut retries = 0;
    let max_retries = 3;

    while total_read < buf.len() {
        match stream.read(&mut buf[total_read..]) {
            Ok(0) => {
                return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "Stream closed"));
            }
            Ok(n) => {
                total_read += n;
                if total_read < buf.len() {
                    retries += 1;
                    if retries > max_retries {
                        println!("Failed to fill buffer after {} retries", retries);
                        return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "Failed to fill buffer after retries"));
                    }
                }
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}