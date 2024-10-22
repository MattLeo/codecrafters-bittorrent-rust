use core::str;
use std::{env, fs::{self, File}, io::{Read, Write}, net::TcpStream, path::{PathBuf, Path}};
use sha1::{Digest, Sha1};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_bytes::ByteBuf;

#[derive(Debug, Serialize, Deserialize, Clone)]
struct TorrentInfo {
    length: i64,
    name: String,
    #[serde(rename = "piece length")]
    piece_length: i64,
    pieces: ByteBuf,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Torrent {
    announce: String,
    info: TorrentInfo,
}

impl Torrent {
    fn new<T: Into<PathBuf>>(file_name: T) -> Result<Torrent, Box<dyn std::error::Error>> {
        let mut file = File::open(file_name.into())?;
        let mut contents = Vec::new();
        file.read_to_end(&mut contents)?;
        let torrent: Torrent = serde_bencode::from_bytes(&contents)?;
        Ok(torrent)
    }

    fn info_hash(&self) -> Result<String, Box<dyn std::error::Error>> {
        let bencoded = serde_bencode::to_bytes(&self.info)?;
        let mut hasher = Sha1::new();
        hasher.update(&bencoded);
        let result = hasher.finalize();
        Ok(hex::encode(result))
    }

    fn validate_piece(&self, piece_index: &u32, piece_hash: String) -> bool {
        let start = *piece_index as usize * 20;
        let meta_hash = &self.info.pieces[start..start + 20];
        let meta_hash_hex = hex::encode(meta_hash);
        return meta_hash_hex == piece_hash;
    }
}

struct TrackerRequest {
    url: String,
    info_hash: String,
    peer_id: String,
    port: i16,
    uploaded: i64,
    downloaded: i64,
    left: i64,
    compact: i16,
}

impl TrackerRequest {
    fn new(url: String, info_hash: String, left: i64) -> TrackerRequest {
        let byte_array: Vec<u8> = hex::decode(info_hash).unwrap();
        let encoded_hash = TrackerRequest::url_encode(byte_array);

        TrackerRequest {
            url,
            info_hash: encoded_hash,
            peer_id: "TestRTAAA11234567899".to_string(),
            port: 6881,
            uploaded: 0,
            downloaded: 0,
            left,
            compact: 1,
        }
    }

    fn url_encode(bytes: Vec<u8>) -> String {
        bytes.iter()
            .map(|&b| {
                match b {
                    b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => (b as char).to_string(),
                    _=> format!("%{:02X}", b)
                }
            })
            .collect::<String>()
    }

    fn get_response(&self) -> Result<Box<[u8]>, Box<dyn std::error::Error>> {
        let request_url = format!(
            "{}?info_hash={}&peer_id={}&port={}&uploaded={}&downloaded={}&left={}&compact={}",
            self.url,
            self.info_hash,
            self.peer_id,
            self.port,
            self.uploaded,
            self.downloaded,
            self.left,
            self.compact,
        );
        let response= reqwest::blocking::get(request_url)?;
        
        if response.status().is_success() {
            let bytes: Vec<u8> = response.bytes()?.to_vec();
            Ok(bytes.into_boxed_slice())
        } else{
            Err(format!("HTTP Error: {}", response.status()).into())
        }        
    }
}

#[allow(dead_code)]
#[derive(Debug, Serialize, Deserialize)]
struct TrackerResponse {
    complete: i32,
    incomplete: i32,
    downloaded: i32,
    interval: i32,
    #[serde(rename = "min interval")]
    min_interval: i32,
    peers: Vec<PeerData>,
}

impl TrackerResponse {
    fn new(byte_array: &[u8]) -> Result<TrackerResponse, Box<dyn std::error::Error>> {
        let mut i = 0;
        let mut complete = 0;
        let mut downloaded = 0;
        let mut incomplete = 0;
        let mut interval = 0;
        let mut min_interval = 0;
        let mut peers: Vec<PeerData> = Vec::new();

        if byte_array[i] != b'd' {
            return Err("Tracker Response is not a dictionary".into());
        }
        i += 1;
        while i < byte_array.len() && byte_array[i] != b'e' {
            let colon_pos = byte_array[i..].iter().position(|&b| b == b':')
                .ok_or("Invalid bencoded message received. Unable to locate key.")?;
            let key_len: usize = std::str::from_utf8(&byte_array[i..i + colon_pos])?
                .parse()?;
            i += colon_pos + 1;

            if i + key_len > byte_array.len() {
                return Err("Key length exceeds remaining data".into());
            }

            let key = std::str::from_utf8(&byte_array[i..i+key_len])?;
            i += key_len;

            match key {
                "complete" => {
                    (complete, i) = TrackerResponse::extract_int(byte_array, i)?;
                },
                "downloaded" => {
                    (downloaded, i) = TrackerResponse::extract_int(byte_array, i)?;
                },
                "incomplete" => {
                    (incomplete, i) = TrackerResponse::extract_int(byte_array, i)?;
                },
                "interval" => {
                    (interval, i) = TrackerResponse::extract_int(byte_array, i)?;
                },
                "min interval" => {
                    (min_interval, i) = TrackerResponse::extract_int(byte_array, i)?;
                },
                "peers" => {
                    let colon_pos = byte_array[i..].iter().position(|&b| b == b':')
                        .ok_or("Invalud 'peers' encoding")?;
                    let peers_len: usize = std::str::from_utf8(&byte_array[i..i + colon_pos])?
                        .parse()?;
                    i += colon_pos + 1;
                    let peers_data = &byte_array[i..i + peers_len];
                    for chunk in peers_data.chunks(6) {
                        if chunk.len() == 6 {
                            let ip = format!("{}.{}.{}.{}", chunk[0], chunk[1], chunk[2], chunk[3]);
                            let port = u16::from_be_bytes([chunk[4], chunk[5]]);
                            let peer= PeerData {ip, port};
                            peers.push(peer);
                        } else {
                            return Err("Malformed peer data received".into());
                        }
                    }
                    break;
                },
                _=> {
                    return Err("Invalid key received in response".into());
                }
            }
        }
        Ok (TrackerResponse {
            complete,
            downloaded,
            incomplete,
            interval,
            min_interval,
            peers
        })
    }

    fn extract_int(byte_array: &[u8], mut i: usize) -> Result<(i32, usize), Box<dyn std::error::Error>> {
        if byte_array[i] != b'i' {
            return Err("Key's value is not an integer".into());
        }
        i += 1;
        let end = byte_array[i..].iter().position(|&b| b == b'e')
            .ok_or("Invalid integer encoding")?;
        let return_value = std::str::from_utf8(&byte_array[i..i+end])?.parse::<i32>()?;
        i += end + 1;
        Ok((return_value, i))
    }
}

#[allow(dead_code)]
#[derive(Debug, Serialize, Deserialize)]
struct PeerData {
    ip: String,
    port: u16,
}


struct Handshake {
    plen: u8,
    protocol: &'static[u8],
    reserved: [u8; 8],
    infohash: Vec<u8>,
    client_id: Vec<u8>,
}

impl Handshake {
    fn new(info_hash: String, client: String) -> Handshake {
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

    fn get(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.push(self.plen);
        bytes.extend_from_slice(self.protocol);
        bytes.extend_from_slice(&self.reserved);
        bytes.extend_from_slice(&self.infohash);
        bytes.extend_from_slice(&self.client_id);

        bytes
    }
}

fn decode_bencoded_value(encoded_value: &[u8]) -> Result<(Value, usize), Box<dyn std::error::Error>> {
    match encoded_value.get(0) {
        Some(b'i') => {
            let end = encoded_value.iter().position(|&b| b == b'e')
                .ok_or("Invalid integer encoding")?;
            let number = str::from_utf8(&encoded_value[1..end])?.parse::<i64>()?;
            Ok((Value::Number(number.into()), end + 1))
        }
        Some(b'l') => {
            let mut list = Vec::new();
            let mut index = 1;
                while encoded_value[index] != b'e' {
                    let (item, consumed) = decode_bencoded_value(&encoded_value[index..])?;
                    list.push(item);
                    index += consumed;
                }
            Ok((Value::Array(list), index + 1))
        }
        Some(b'd') => {
            let mut dict = serde_json::Map::new();
            let mut index = 1;
            while encoded_value[index] != b'e' {
                let (key, key_consumed) = decode_bencoded_value(&encoded_value[index..])?;
                index += key_consumed;
                let (value, value_consumed) = decode_bencoded_value(&encoded_value[index..])?;
                index += value_consumed;
                if let Value::String(key) = key {
                    dict.insert(key, value);
                } else {
                    return Err("Invalid dictionary key".into());
                }
            }
            Ok((Value::Object(dict), index + 1))
        }
        Some(b) if b.is_ascii_digit() => {
            let colon_index = encoded_value.iter().position(|&b| b == b':')
                .ok_or("Invalid string encoding")?;
            let length: usize = str::from_utf8(&encoded_value[..colon_index])?.parse()?;
            let start = colon_index + 1;
            let end = start + length;
            let string = str::from_utf8(&encoded_value[start..end])?;
            Ok((Value::String(string.to_string()), end))
        }
        _ => Err("Invalid bencode format".into())
    }
}

fn calc_block_size(piece_len: u32, block_size: u32, block_index: u32) -> u32 {
    let full_blocks = piece_len / block_size;
    let last_block = piece_len % block_size;

    if block_index < full_blocks {
        block_size
    } else {
        last_block
    }
}

fn send_message(message_type: &str, stream: &mut TcpStream, piece_index: &u32, block_offset: u32, block_length: u32) -> Result<(), Box<dyn std::error::Error>> {
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

fn recieve_response(stream: &mut TcpStream) -> Result<Option<(u32, u32, Vec<u8>)>, Box<dyn std::error::Error>> {
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

fn join_blocks(blocks: Vec<(u32, Vec<u8>)>, peice_length: u32) -> Vec<u8> {
    let mut piece_buffer = vec![0u8; peice_length as usize];
    for (block_offset, block_data) in blocks {
        let offset = block_offset as usize;
        let end = offset + block_data.len();
        piece_buffer[offset..end].copy_from_slice(&block_data);
    }

    piece_buffer
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

fn join_pieces(pieces: Vec<(u32, Vec<u8>)>, file_length: u32) -> Vec<u8> {
    let mut file_buffer = vec![0u8; file_length as usize];
    let mut sorted_pieces = pieces;
    sorted_pieces.sort_by_key(|(offset, _)| *offset);
    let piece_length = sorted_pieces[0].1.len(); 
    
    for (piece_index, (_offset, piece_data)) in sorted_pieces.into_iter().enumerate() {
        let start = piece_index * piece_length;
        let end = start + piece_data.len();
        file_buffer[start..end].copy_from_slice(&piece_data);
    }
    
    file_buffer
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: {} <command> <argument>", args[0]);
        return Ok(());
    }
    
    let command = &args[1];
    let argument = &args[2];

    match command.trim().to_lowercase().as_str() {
        "decode" => {
            let decoded_value = (decode_bencoded_value(argument.as_bytes())?).0;
            println!("{}", serde_json::to_string(&decoded_value)?);
        },

        "info" => {
            let torrent = Torrent::new(PathBuf::from(argument))?;
            let info_hash = torrent.info_hash()?;
            
            println!("Tracker URL: {}", torrent.announce);
            println!("Length: {}", torrent.info.length);
            println!("Info Hash: {}", info_hash);
            println!("Piece Length: {}", torrent.info.piece_length);
            println!("Piece Hashes: {}", hex::encode(torrent.info.pieces));
        },

        "peers" => {
            let torrent = Torrent::new(PathBuf::from(argument))?;
            let info_hash = torrent.info_hash()?;
            let request = TrackerRequest::new(torrent.announce, info_hash, torrent.info.length);
            let response = request.get_response().unwrap();
            let tracker_info: TrackerResponse = TrackerResponse::new(&*response)?;

            for peer in tracker_info.peers {
                println!("{}:{}", peer.ip, peer.port);
            }
        },

        "handshake" => {
            let torrent = Torrent::new(PathBuf::from(argument))?;
            let client_id = "TestRTAAA11234567899".to_string();
            let handshake = Handshake::new(torrent.info_hash()?, client_id);
            let mut response = [0u8; 68];

            let mut stream = TcpStream::connect(&args[3])?;
            stream.write_all(&handshake.get())?;
            stream.read_exact(&mut response)?;

            let peer_id = hex::encode(&response[48..]);
            println!("Peer ID: {}", peer_id);
        },

        "download_piece" => {
            let output_path = Path::new(&args[3]);
            if let Some(parent_dir) = output_path.parent() {
                fs::create_dir_all(parent_dir)?
            }
            let mut file = File::create(output_path)?;
            let piece_index = &args[5].parse::<u32>()?;
            let max_requests = 5;

            let torrent = Torrent::new(PathBuf::from(&args[4]))?;
            let total_file_length = torrent.info.length.clone() as u32;
            let mut piece_length = torrent.info.piece_length.clone() as u32;
            let total_pieces = (total_file_length as f64 / piece_length as f64).ceil() as u32;
            if *piece_index == total_pieces - 1 {
                let mut last_piece_length = total_file_length % piece_length;
                if last_piece_length == 0 {
                    last_piece_length = piece_length;
                }
                piece_length = last_piece_length;
            }
            let torrent_clone = torrent.clone();
            let info_hash = torrent.info_hash()?;
            let info_hash_clone = info_hash.clone();
            let client_id = "TestRTAAA11234567899".to_string();
            let request = TrackerRequest::new(torrent.announce, info_hash, torrent.info.length);
            let response = request.get_response().unwrap();
            let tracker_info: TrackerResponse = TrackerResponse::new(&*response)?;
            let handshake = Handshake::new(info_hash_clone, client_id);
            let mut handshake_response = [0u8; 68];
            let peer = &tracker_info.peers[0];
            
            let mut stream = TcpStream::connect(format!("{}:{}",peer.ip, peer.port ))?;
            stream.write_all(&handshake.get())?;
            stream.read_exact(&mut handshake_response)?;
            let _bitfield = recieve_response(&mut stream)?;

            let mut block_offset: u32 = 0;
            let mut pending_requests: usize = 0;
            let mut blocks: Vec<(u32,Vec<u8>)> = Vec::new();
            let mut block_size: u32 = 16 * 1024;

            send_message("interested", &mut stream, piece_index, block_offset, block_size)?;
            let _unchoke = recieve_response(&mut stream)?;
            let mut block_index = 0;

            while block_offset < piece_length as u32 {
                if block_offset < piece_length as u32 && pending_requests < max_requests {
                    println!("Sending request");
                    send_message("request", &mut stream, piece_index, block_offset, block_size)?;
                    println!("{} offset of {} total", block_offset, piece_length);
                    block_offset += block_size;
                    pending_requests += 1;
                    block_index += 1;
                    block_size = calc_block_size(piece_length, block_size, block_index);
                }

                match recieve_response(&mut stream)? {
                    Some((_received_piece_index, received_block_offset, block_data)) => {
                        println!("Received block");
                        blocks.push((received_block_offset, block_data));
                        pending_requests -= 1;
                    }
                    None => {}
                }
            }
            

            let full_piece = join_blocks(blocks, piece_length as u32);
            let mut hasher = Sha1::new();
            hasher.update(&full_piece);
            let full_piece_hash = hex::encode(hasher.finalize());

            if torrent_clone.validate_piece(piece_index, full_piece_hash) {
                file.write_all(&full_piece)?;
            } else {
                eprintln!("Recieved piece does not match hash data");
            }
        }

        "download" => {
            let output_path = Path::new(&args[3]);
            if let Some(parent_dir) = output_path.parent() {
                fs::create_dir_all(parent_dir)?
            }
            let mut file = File::create(output_path)?;
            let max_requests = 5;

            let torrent = Torrent::new(PathBuf::from(&args[4]))?;
            let total_file_length = torrent.info.length.clone() as u32;
            let total_pieces = (total_file_length as f64 / torrent.info.piece_length.clone() as f64).ceil() as u32;
            
            let torrent_clone = torrent.clone();
            let info_hash = torrent.info_hash()?;
            let info_hash_clone = info_hash.clone();
            let client_id = "TestRTAAA11234567899".to_string();
            let request = TrackerRequest::new(torrent.announce, info_hash, torrent.info.length);
            let response = request.get_response().unwrap();
            let tracker_info: TrackerResponse = TrackerResponse::new(&*response)?;
            let handshake = Handshake::new(info_hash_clone, client_id);
            let mut handshake_response = [0u8; 68];
            let peer = &tracker_info.peers[0];
            
            let mut stream = TcpStream::connect(format!("{}:{}",peer.ip, peer.port ))?;
            stream.write_all(&handshake.get())?;
            stream.read_exact(&mut handshake_response)?;
            let _bitfield = recieve_response(&mut stream)?;
            let mut pieces: Vec<(u32,Vec<u8>)> = Vec::new();
            send_message("interested", &mut stream, &0, 0, 0)?;
            let _unchoke = recieve_response(&mut stream)?;

            for piece_index in 0..total_pieces {
                let mut block_offset: u32 = 0;
                let mut pending_requests: usize = 0;
                let mut blocks: Vec<(u32,Vec<u8>)> = Vec::new();
                let mut block_size: u32 = 16 * 1024;
                let mut piece_length = torrent.info.piece_length.clone() as u32;
                let mut block_index = 0;
                if piece_index == total_pieces - 1 {
                    let mut last_piece_length = total_file_length % piece_length;
                    if last_piece_length == 0 {
                        last_piece_length = piece_length;
                    }
                    piece_length = last_piece_length;
                }
                
                while block_offset < piece_length as u32 {
                    if block_offset < piece_length as u32 && pending_requests < max_requests {
                        println!("Sending request");
                        send_message("request", &mut stream, &piece_index, block_offset, block_size)?;
                        println!("{} offset of {} total", block_offset, piece_length);
                        block_offset += block_size;
                        pending_requests += 1;
                        block_index += 1;
                        block_size = calc_block_size(piece_length, block_size, block_index);
                    }
    
                    match recieve_response(&mut stream)? {
                        Some((_received_piece_index, received_block_offset, block_data)) => {
                            println!("Received block");
                            blocks.push((received_block_offset, block_data));
                            pending_requests -= 1;
                        }
                        None => {}
                    }
                }

                let full_piece = join_blocks(blocks, piece_length as u32);
                let mut hasher = Sha1::new();
                hasher.update(&full_piece);
                let full_piece_hash = hex::encode(hasher.finalize());
    
                if torrent_clone.validate_piece(&piece_index, full_piece_hash) {
                    pieces.push((piece_length, full_piece));
                } else {
                    eprintln!("Recieved piece does not match hash data");
                }
            }
            let full_file = join_pieces(pieces, total_file_length);
            file.write_all(&full_file)?;
        } 

        _ => eprintln!("Unknown command: {}", command),
    }

    Ok(())
}
