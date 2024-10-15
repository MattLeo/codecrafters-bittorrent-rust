use std::env;
use std::path::PathBuf;
use std::fs::File;
use std::io::Read;
use std::str;
use sha1::{Sha1, Digest};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_bytes::ByteBuf;

#[derive(Debug, Serialize, Deserialize)]
struct Torrent {
    announce: String,
    info: TorrentInfo,
}

#[derive(Debug, Serialize, Deserialize)]
struct TorrentInfo {
    length: i64,
    name: String,
    #[serde(rename = "piece length")]
    piece_length: i64,
    pieces: ByteBuf,
}

fn calculate_info_hash(info: &TorrentInfo) -> Result<String, Box<dyn std::error::Error>> {
    let bencoded = serde_bencode::to_bytes(info)?;
    let mut hasher = Sha1::new();
    hasher.update(&bencoded);
    let result = hasher.finalize();
    Ok(hex::encode(result))
}

fn parse_torrent<T: Into<PathBuf>>(file_name: T) -> Result<Torrent, Box<dyn std::error::Error>> {
    let mut file = File::open(file_name.into())?;
    let mut contents = Vec::new();
    file.read_to_end(&mut contents)?;
    
    let torrent: Torrent = serde_bencode::from_bytes(&contents)?;
    Ok(torrent)
}

fn decode_bencoded_value(encoded_value: &[u8]) -> Result<Value, Box<dyn std::error::Error>> {
    let (value, _) = decode_bencoded_value_inner(encoded_value)?;
    Ok(value)
}

fn decode_bencoded_value_inner(encoded_value: &[u8]) -> Result<(Value, usize), Box<dyn std::error::Error>> {
    match encoded_value.get(0) {
        Some(b'i') => decode_integer(encoded_value),
        Some(b'l') => decode_list(encoded_value),
        Some(b'd') => decode_dict(encoded_value),
        Some(b) if b.is_ascii_digit() => decode_string(encoded_value),
        _ => Err("Invalid bencode format".into()),
    }
}

fn decode_integer(encoded_value: &[u8]) -> Result<(Value, usize), Box<dyn std::error::Error>> {
    let end = encoded_value.iter().position(|&b| b == b'e')
        .ok_or("Invalid integer encoding")?;
    let number = str::from_utf8(&encoded_value[1..end])?.parse::<i64>()?;
    Ok((Value::Number(number.into()), end + 1))
}

fn decode_string(encoded_value: &[u8]) -> Result<(Value, usize), Box<dyn std::error::Error>> {
    let colon_index = encoded_value.iter().position(|&b| b == b':')
        .ok_or("Invalid string encoding")?;
    let length: usize = str::from_utf8(&encoded_value[..colon_index])?.parse()?;
    let start = colon_index + 1;
    let end = start + length;
    let string = str::from_utf8(&encoded_value[start..end])?;
    Ok((Value::String(string.to_string()), end))
}

fn decode_list(encoded_value: &[u8]) -> Result<(Value, usize), Box<dyn std::error::Error>> {
    let mut list = Vec::new();
    let mut index = 1;
    while encoded_value[index] != b'e' {
        let (item, consumed) = decode_bencoded_value_inner(&encoded_value[index..])?;
        list.push(item);
        index += consumed;
    }
    Ok((Value::Array(list), index + 1))
}

fn decode_dict(encoded_value: &[u8]) -> Result<(Value, usize), Box<dyn std::error::Error>> {
    let mut dict = serde_json::Map::new();
    let mut index = 1;
    while encoded_value[index] != b'e' {
        let (key, key_consumed) = decode_bencoded_value_inner(&encoded_value[index..])?;
        index += key_consumed;
        let (value, value_consumed) = decode_bencoded_value_inner(&encoded_value[index..])?;
        index += value_consumed;
        if let Value::String(key) = key {
            dict.insert(key, value);
        } else {
            return Err("Invalid dictionary key".into());
        }
    }
    Ok((Value::Object(dict), index + 1))
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
            let decoded_value = decode_bencoded_value(argument.as_bytes())?;
            println!("{}", serde_json::to_string(&decoded_value)?);
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
