use serde_bytes::ByteBuf;
use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};
use std::{path::PathBuf, fs::File, io::Read};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TorrentInfo {
    pub length: u32,
    pub name: String,
    #[serde(rename = "piece length")]
    pub piece_length: u32,
    pub pieces: ByteBuf,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Torrent {
    pub announce: String,
    pub info: TorrentInfo,
}

#[allow(dead_code)]
impl Torrent {
    pub fn new<T: Into<PathBuf>>(file_name: T) -> Result<Torrent, Box<dyn std::error::Error>> {
        let mut file = File::open(file_name.into())?;
        let mut contents = Vec::new();
        file.read_to_end(&mut contents)?;
        let torrent: Torrent = serde_bencode::from_bytes(&contents)?;
        Ok(torrent)
    }

    pub fn info_hash(&self) -> Result<String, Box<dyn std::error::Error>> {
        let bencoded = serde_bencode::to_bytes(&self.info)?;
        let mut hasher = Sha1::new();
        hasher.update(&bencoded);
        let result = hasher.finalize();
        Ok(hex::encode(result))
    }

    pub fn validate_piece(&self, piece_index: &u32, piece_hash: String) -> bool {
        let start = *piece_index as usize * 20;
        let meta_hash = &self.info.pieces[start..start + 20];
        let meta_hash_hex = hex::encode(meta_hash);
        return meta_hash_hex == piece_hash;
    }

    pub fn magnet(bytes: &[u8]) -> Result<TorrentInfo, Box<dyn std::error::Error>> {
        let torrent_info: TorrentInfo = serde_bencode::from_bytes(&bytes)?;
        Ok(torrent_info)
    }
}

#[allow(dead_code)]
#[derive(Clone)]
pub struct MagnetInfo {
    pub tracker_url: String,
    pub filename: String,
    pub info_hash: String,
}

impl MagnetInfo {
    pub fn new(encoded_text: &str) -> Result<MagnetInfo, Box<dyn std::error::Error>> {
        if !encoded_text.starts_with("magnet:?") {
            return Err("Invalid magnet link".into());
        }
        let mut info_hash: Option<&str> = None;
        let mut filename: Option<&str> = None;
        let mut tracker_url: Option<&str> = None;

        for param in encoded_text[8..].split("&") {
            if let Some((key, value)) = param.split_once("=") {
                match key {
                   "xt" => { info_hash = Some(&value[9..]); },
                   "dn" => { filename = Some(value); },
                   "tr" => { tracker_url = Some(value); },
                   _ => { return Err("Invalid key found in magnet link".into()); }, 
                }
            }
        }

        let info_hash = info_hash.ok_or("Missing info hash in magnet link")?;
        let filename = filename.ok_or("Missing filename in magnet link")?;
        let tracker_url = tracker_url.ok_or("Missing tracker URL in magnet link")?;

        Ok(MagnetInfo {
            tracker_url: tracker_url.to_string().replace("%3A", ":").replace("%2F", "/"),
            filename: filename.to_string(),
            info_hash: info_hash.to_string(),
        })
    }
}
