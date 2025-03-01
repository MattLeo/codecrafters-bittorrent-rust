use serde::{Deserialize, Serialize};
use crate::peer::PeerData;
use core::str;

#[allow(dead_code)]
pub struct TrackerRequest {
   pub url: String,
   pub info_hash: String,
   pub peer_id: String,
   pub port: u16,
   pub uploaded: u32,
   pub downloaded: u32,
   pub left: u32,
   pub compact: u16,
}

#[allow(dead_code)]
impl TrackerRequest {
    pub fn new(url: String, info_hash: String, left: u32) -> TrackerRequest {
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

    pub fn url_encode(bytes: Vec<u8>) -> String {
        bytes.iter()
            .map(|&b| {
                match b {
                    b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => (b as char).to_string(),
                    _=> format!("%{:02X}", b)
                }
            })
            .collect::<String>()
    }

    pub fn get_response(&self) -> Result<Box<[u8]>, Box<dyn std::error::Error>> {
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

    pub fn magnet_request(url: String, info_hash: String) -> TrackerRequest {
        let byte_array: Vec<u8> = hex::decode(info_hash).unwrap();
        let encoded_hash = TrackerRequest::url_encode(byte_array);
        
        TrackerRequest {
            url,
            info_hash: encoded_hash,
            peer_id: "TestRTAAA11234567899".to_string(),
            port: 6881,
            uploaded: 0,
            downloaded: 0,
            left: 999,
            compact: 1,
        }
    }
}

#[allow(dead_code)]
#[derive(Debug, Serialize, Deserialize)]
pub struct TrackerResponse {
   pub complete: i32,
   pub incomplete: i32,
   pub downloaded: i32,
   pub interval: i32,
    #[serde(rename = "min interval")]
   pub min_interval: i32,
   pub peers: Vec<PeerData>,
}

#[allow(dead_code)]
impl TrackerResponse {
    pub fn new(byte_array: &[u8]) -> Result<TrackerResponse, Box<dyn std::error::Error>> {
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
                "mininterval" => {
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