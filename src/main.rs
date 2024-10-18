use core::str;
use std::env;
use std::path::PathBuf;
use std::fs::File;
use std::io::Read;
use sha1::{Sha1, Digest};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_bytes::ByteBuf;

#[derive(Debug, Serialize, Deserialize)]
struct TorrentInfo {
    length: i64,
    name: String,
    #[serde(rename = "piece length")]
    piece_length: i64,
    pieces: ByteBuf,
}

#[derive(Debug, Serialize, Deserialize)]
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
                    _=> format!("%{:X}", b)
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
        println!("Received data: {:?}", String::from_utf8_lossy(byte_array));
        i += 1;
        while i < byte_array.len() && byte_array[i] != b'e' {
            println!("Parsing at index: {}", i);
            let colon_pos = byte_array[i..].iter().position(|&b| b == b':')
                .ok_or("WHAT.")?;
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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: {} <command> <argument>", args[0]);
        return Ok(());
    }
    
    let command = &args[1];
    let argument = &args[2];

    match command.as_str() {
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
        }

        _ => eprintln!("Unknown command: {}", command),
    }

    Ok(())
}
