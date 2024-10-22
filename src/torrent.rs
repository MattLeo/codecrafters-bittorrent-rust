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
}