use std::{env, fs::{self, File}, io::{Read, Write}, net::TcpStream, path::{PathBuf, Path}};
use sha1::{Digest, Sha1};
use bittorrent_starter_rust::{torrent, tracker, transceive, file_utils};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprint!("Usage: {} <command> <arguments>", args[0]);
        return Ok(());
    }
    let command = &args[1];
    let argument = &args[2];

    match command.as_str() {
        "decode" => print_decode(argument),
        "info" => list_info(argument),
        "peers" => list_peers(argument),
        "handshake" => show_handshake(argument, &args[3]),
        "download_piece" => download_part(&args[3..]),
        "download" => download_full(&args[3..]),
        _ => {
            eprintln!("Unknown command: {}", command);
            Ok(())
        }
    }
}

fn print_decode(argument: &str) -> Result<(), Box<dyn std::error::Error>> {
    let decoded_value = (file_utils::decode_bencoded_value(argument.as_bytes())?).0;
    println!("{}", serde_json::to_string(&decoded_value)?);
    Ok(())
}

fn list_info(path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let torrent = torrent::Torrent::new(PathBuf::from(path))?;
    let info_hash = torrent.info_hash()?;

    println!("Tracker URL: {}", torrent.announce);
    println!("Length: {}", torrent.info.length);
    println!("Info Hash: {}", info_hash);
    println!("Piece Length: {}", torrent.info.piece_length);
    println!("Piece Hashes: {}", hex::encode(torrent.info.pieces));
    Ok(())
}

fn list_peers(path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let torrent = torrent::Torrent::new(PathBuf::from(path))?;
    let info_hash = torrent.info_hash()?;
    let request = tracker::TrackerRequest::new(torrent.announce, info_hash, torrent.info.length);
    let response = request.get_response().unwrap();
    let tracker_info = tracker::TrackerResponse::new(&*response)?;

    for peer in tracker_info.peers {
        println!("{}:{}", peer.ip, peer.port);
    }
    Ok(())
}

fn show_handshake(path: &str, peer_addr: &str) -> Result<(), Box<dyn std::error::Error>> {
    let torrent = torrent::Torrent::new(PathBuf::from(path))?;
    let client_id = "TestRTAAA11234567899".to_string();
    let handshake = transceive::Handshake::new(torrent.info_hash()?, client_id);
    let mut response = [0u8; 68];

    let mut stream = TcpStream::connect(peer_addr)?;
    stream.write_all(&handshake.get())?;
    stream.read_exact(&mut response)?;

    println!("Peer ID: {}", hex::encode(&response[48..]));
    Ok(())
}

fn download_part(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let output_path = Path::new(&args[0]);
    if let Some(parent_dir) = output_path.parent() {
        fs::create_dir_all(parent_dir)?;
    }

    let piece_index = args[2].parse::<u32>()?;
    let torrent = torrent::Torrent::new(PathBuf::from(&args[1]))?;
    let (stream, _) = transceive::setup_connection(&torrent)?;

    let piece_length = if piece_index == (torrent.info.length as f64 / torrent.info.piece_length as f64).ceil() as u32 - 1 {
    let last_piece_length = (torrent.info.length as u32) % (torrent.info.piece_length as u32);
    if last_piece_length == 0 { torrent.info.piece_length as u32} else {last_piece_length}
    } else {
        torrent.info.piece_length as u32
    };

    let mut context = transceive::DownloadContext::new(stream, piece_length, 5); 

    let piece_data = context.download_piece(&piece_index)?;
    let mut hasher = Sha1::new();
    hasher.update(&piece_data);
    let piece_hash = hex::encode(hasher.finalize());

    if torrent.validate_piece(&piece_index, piece_hash) {
        File::create(output_path)?.write_all(&piece_data)?;

        Ok(())
    } else {
        Err("Received peice does not match hash data".into())
    }
}

fn download_full(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let output_path = Path::new(&args[0]);
    if let Some(parent_dir) = output_path.parent() {
        fs::create_dir_all(parent_dir)?;
    }
    
    let torrent = torrent::Torrent::new(PathBuf::from(&args[1]))?;
    let total_file_length = torrent.info.length as u32;
    let total_pieces = ((total_file_length as f64) / (torrent.info.piece_length as f64)).ceil() as u32;

    let (stream, _) = transceive::setup_connection(&torrent)?;
    let mut pieces  = Vec::new();

    let mut context = transceive::DownloadContext::new(stream, torrent.info.piece_length, 5); 

    for piece_index in 0..total_pieces {
        if piece_index == total_pieces -1 {
            let last_piece_length = total_file_length % (torrent.info.piece_length as u32);
            context.piece_length = if last_piece_length == 0 {
                torrent.info.piece_length as u32
            } else {
                last_piece_length
            };
        }

        let piece_data = context.download_piece(&piece_index)?;
        let mut hasher = Sha1::new();
        hasher.update(&piece_data);
        let piece_hash = hex::encode(hasher.finalize());

        if torrent.validate_piece(&piece_index, piece_hash) {
            pieces.push((context.piece_length, piece_data));
        } else {
            return Err("Received piece does not match hash data".into());
        }
    }

    let full_file = file_utils::join_pieces(pieces, total_file_length);
    File::create(output_path)?.write_all(&full_file)?;
    Ok(())
}