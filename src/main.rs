mod torrent;
mod bencode;

use std::env;
use std::path::PathBuf;
use sha1::{Sha1, Digest};
use torrent::{Torrent, TorrentInfo, parse_torrent};
use bencode::decode_bencoded_value;

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
            let decoded_value = decode_bencoded_value(argument.as_bytes())?;
            println!("{}", serde_json::to_string_pretty(&decoded_value)?);
        },
        "info" => {
            let torrent = parse_torrent(PathBuf::from(argument))?;
            let info_hash = calculate_info_hash(&torrent.info)?;
            
            println!("Tracker URL: {}", torrent.announce);
            println!("Length: {}", torrent.info.length);
            println!("Info Hash: {}", info_hash);
        },
        _ => eprintln!("Unknown command: {}", command),
    }

    Ok(())
}

fn calculate_info_hash(info: &TorrentInfo) -> Result<String, Box<dyn std::error::Error>> {
    let bencoded = serde_bencode::to_bytes(info)?;
    let mut hasher = Sha1::new();
    hasher.update(&bencoded);
    let result = hasher.finalize();
    Ok(hex::encode(result))
}