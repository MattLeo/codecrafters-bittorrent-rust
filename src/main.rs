use serde_json;
use std::{env, path::PathBuf, fs::File, io::Read};
use reqwest::Url;
use sha1::{Sha1, Digest};
use serde_bencode::ser;
use serde::{Deserialize, Serialize};

#[allow(dead_code)]


struct Torrent {
    announce: reqwest::Url,
    info: TorrentInfo,
}

#[derive(Serialize, Deserialize)]
struct TorrentInfo {
    length: i64,
    name: String,
    #[serde(rename = "piece length")]
    piece_length: i64,
    pieces: Vec<u8>,
}

fn parse_torrent<T>(file_name: T) -> Result<Torrent, Box<dyn std::error::Error>>
where
    T: Into<PathBuf>,
{
    let mut file = File::open(file_name.into())?;
    let mut encoded_value= Vec::new();
    file.read_to_end(&mut encoded_value)?;
    let data = decode_bencoded_value(&encoded_value).0;

    let announce_url = if let Some(url_value) = data.get("announce") {
        if let Some(url_str) = url_value.as_str() {
            Url::parse(url_str)?
        } else {
            return Err("announce URL is not a valid string".into());
        }
    } else {
        return Err("announce URL not found".into());
    };


    let info = if let Some(info_value) = data.get("info") {
        if let serde_json::Value::Object(info_dict) = info_value {
            TorrentInfo {
                length: info_dict
                    .get("length")
                    .and_then(|v| v.as_i64())
                    .ok_or("Missing or invalid 'length'")?,
                name: info_dict
                    .get("name")
                    .and_then(|v| v.as_str())
                    .ok_or("Missing or invalid 'name'")?
                    .to_string(),
                piece_length: info_dict
                    .get("piece length")
                    .and_then(|v| v.as_i64())
                    .ok_or("Missing or invalid 'pieces length'")?,
                pieces: info_dict
                    .get("pieces")
                    .and_then(|v| v.as_str())
                    .ok_or("Invalid or missing 'peices'")?
                    .as_bytes()
                    .to_vec(),
            }
        } else {
            return Err("Invalid 'info' section".into());
        }
    } else {
        return Err("'info' section missing".into());
    };

    Ok(Torrent {
        announce: announce_url,
        info,
    })
}

fn decode_bencoded_value(encoded_value: &[u8]) -> (serde_json::Value, usize) {
    let ident = encoded_value[0] as char;

    if ident.is_digit(10) {
        let colon_index = encoded_value.iter().position(|&b| b == b':').unwrap();
        let number = std::str::from_utf8(&encoded_value[..colon_index])
            .unwrap()
            .parse::<usize>()
            .unwrap();
        let consumed = colon_index + 1 + number;
        let string = &encoded_value[colon_index + 1..consumed];
        if let Ok(utf8_string) = std::str::from_utf8(string) {
        (serde_json::Value::String(utf8_string.to_string()), consumed)
        } else {
            (serde_json::Value::Array(string.iter().map(|&b| serde_json::Value::Number(b.into())).collect()), consumed)
        }
    } else if ident == 'i' {
        let e_index = encoded_value.iter().position(|&b| b == b'e').unwrap();
        let number = std::str::from_utf8(&encoded_value[1..e_index])
            .unwrap()
            .parse::<i64>()
            .unwrap();
        let consumed = e_index + 1;
        (serde_json::Value::Number(serde_json::Number::from(number)), consumed)
    } else if ident == 'l' {
        let mut list = Vec::new();
        let mut rest = &encoded_value[1..];
        let mut consumed= 1;
        while rest[0] != b'e' {
            let (item,length) = decode_bencoded_value(rest);
            list.push(item);
            rest = &rest[length..];
            consumed += length;
        }
        consumed += 1;
        (serde_json::Value::Array(list), consumed)
    } else if ident == 'd' {
        let mut dict = serde_json::Map::new();
        let mut rest = &encoded_value[1..];
        let mut consumed = 1;
        while rest[0] != b'e' {
            let (key, key_length) = decode_bencoded_value(rest);
            let key = match key {
                serde_json::Value::String(key) => key,
                _ => return (serde_json::Value::Null, consumed)
            };
            rest = &rest[key_length..];
            consumed += key_length;
            let (val, val_length) = decode_bencoded_value(rest);
            dict.insert(key, val);
            rest = &rest[val_length..];
            consumed += val_length;
        }
        consumed += 1;
        (serde_json::Value::Object(dict), consumed)
    } else {
        panic!("Unhandled encoded value");
    }
}

// Usage: your_bittorrent.sh decode "<encoded_value>"
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: {} decode <encoded_value>", args[0]);
        return Ok(());
    }
    let command = &args[1];

    if command == "decode" {
        let encoded_value = args[2].as_bytes();
        let decoded_value = decode_bencoded_value(encoded_value);
        println!("{}", decoded_value.0);
    } else if command == "info" {
        let file_name = &args[2];
        let torrent = parse_torrent(file_name)?;
        let bencoded = ser::to_bytes(&torrent.info)?;
        let mut hasher = Sha1::new();
        hasher.update(&bencoded);
        let result = hasher.finalize();
        let hash = hex::encode(result);

        println!("Tracker URL: {}", torrent.announce);
        println!("Length: {}", torrent.info.length);
        println!("Info Hash: {}", hash);
    } else {
        eprintln!("unknown command: {}", command);
    }

    Ok(())
}