use std::{env, fs::{self, File}, io::Write, path::{Path, PathBuf}};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use sha1::{Digest, Sha1};
use bittorrent_starter_rust::{torrent, tracker, transceive, file_utils, peer};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprint!("Usage: {} <command> <arguments>", args[0]);
        return Ok(());
    }
    let command = &args[1];
    let argument = &args[2];

    match command.as_str() {
        "decode" => print_decode(argument).await,
        "info" => list_info(argument).await,
        "peers" => list_peers(argument).await,
        "handshake" => show_handshake(argument, &args[3]).await,
        "download_piece" => download_part(&args[3..]).await,
        "download" => download_full(&args[3..]).await,
        "magnet_parse" => parse_magnet(argument).await,
        "magnet_handshake" => magnet_handshake(argument).await,
        _ => {
            eprintln!("Unknown command: {}", command);
            Ok(())
        }
    }
}

async fn print_decode(argument: &str) -> Result<(), Box<dyn std::error::Error>> {
    let decoded_value = (file_utils::decode_bencoded_value(argument.as_bytes())?).0;
    println!("{}", serde_json::to_string(&decoded_value)?);
    Ok(())
}

async fn list_info(path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let torrent = torrent::Torrent::new(PathBuf::from(path))?;
    let info_hash = torrent.info_hash()?;

    println!("Tracker URL: {}", torrent.announce);
    println!("Length: {}", torrent.info.length);
    println!("Info Hash: {}", info_hash);
    println!("Piece Length: {}", torrent.info.piece_length);
    println!("Piece Hashes: {}", hex::encode(torrent.info.pieces));
    Ok(())
}

async fn list_peers(path: &str) -> Result<(), Box<dyn std::error::Error>> {
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

async fn show_handshake(path: &str, peer_addr: &str) -> Result<(), Box<dyn std::error::Error>> {
    let torrent = torrent::Torrent::new(PathBuf::from(path))?;
    let client_id = "TestRTAAA11234567899".to_string();
    let handshake = transceive::Handshake::new(torrent.info_hash()?, client_id);
    let mut response = [0u8; 68];

    let mut stream = tokio::net::TcpStream::connect(peer_addr).await?;
    stream.write_all(&handshake.get()).await?;
    stream.read_exact(&mut response).await?;

    println!("Peer ID: {}", hex::encode(&response[48..]));
    Ok(())
}

async fn download_part(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let output_path = Path::new(&args[0]);
    if let Some(parent_dir) = output_path.parent() {
        fs::create_dir_all(parent_dir)?;
    }

    let piece_index = args[2].parse::<u32>()?;
    let torrent = torrent::Torrent::new(PathBuf::from(&args[1]))?;
    let info_hash = torrent.info_hash()?;
    let request = tracker::TrackerRequest::new(torrent.announce.clone(), info_hash, torrent.info.length);
    let response = request.get_response()?;
    let tracker_info = tracker::TrackerResponse::new(&*response)?;
    let pool = peer::PeerPool::new(5);

    for peer in &tracker_info.peers {
        if let Err(e) = pool.add_peer(peer, &torrent).await {
            eprintln!("Failed to add peer {}:{} - {}", peer.ip, peer.port, e);
            continue;
        }
    }

    let conn = pool.get_connection().await.ok_or("No peers avilable")?;
    let piece_length = if piece_index == (torrent.info.length as f64 / torrent.info.piece_length as f64).ceil() as u32 - 1 {
        let last_piece_length = (torrent.info.length as u32) % (torrent.info.piece_length as u32);
        if last_piece_length == 0 { torrent.info.piece_length as u32 } else { last_piece_length }
    } else {
        torrent.info.piece_length as u32
    };

    let mut context = transceive::DownloadContext::new(piece_length, 5);
    let piece_data = {
        let mut stream = conn.stream.lock().await;
        let piece_index = piece_index;
    
        Box::pin(async move {
            context.download_piece(&mut *stream, &piece_index).await
        })
        .await?
    };

    let mut hasher = Sha1::new();
    hasher.update(&piece_data);
    let piece_hash = hex::encode(hasher.finalize());
    pool.return_connection(&conn.peer_id, true).await;

    if torrent.validate_piece(&piece_index, piece_hash) {
        File::create(output_path)?.write_all(&piece_data)?;
        Ok(())
    } else {
        Err("Received piece does not match hash data".into())
    }
}

async fn download_full(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let output_path = Path::new(&args[0]);
    if let Some(parent_dir) = output_path.parent() {
        fs::create_dir_all(parent_dir)?;
    }
    
    let torrent = torrent::Torrent::new(PathBuf::from(&args[1]))?;
    let total_file_length = torrent.info.length as u32;
    let total_pieces = ((total_file_length as f64) / (torrent.info.piece_length as f64)).ceil() as u32;
    let info_hash = torrent.info_hash()?;
    let request = tracker::TrackerRequest::new(torrent.announce.clone(), info_hash, torrent.info.length);
    let response = request.get_response()?;
    let tracker_info = tracker::TrackerResponse::new(&*response)?;
    let pool = peer::PeerPool::new(5);
    
    for peer in &tracker_info.peers {
        if let Err(e) = pool.add_peer(peer, &torrent).await {
            eprintln!("Failed to add peer {}:{} - {}", peer.ip, peer.port, e);
            continue;
        }
    }

    let mut pieces = Vec::new();
    let mut context = transceive::DownloadContext::new(torrent.info.piece_length, 5);

    for piece_index in 0..total_pieces {
        let conn = pool.get_connection().await.ok_or("No peers available")?;

        if piece_index == total_pieces - 1 {
            let last_piece_length = total_file_length % (torrent.info.piece_length as u32);
            context.piece_length = if last_piece_length == 0 {
                torrent.info.piece_length as u32
            } else {
                last_piece_length
            };
        }

        let piece_data = {
            let mut stream = conn.stream.lock().await;
            let piece_index = piece_index;
        
            Box::pin(async move {
                context.download_piece(&mut *stream, &piece_index).await
            })
            .await?
        };

        let mut hasher = Sha1::new();
        hasher.update(&piece_data);
        let piece_hash = hex::encode(hasher.finalize());

        pool.return_connection(&conn.peer_id, true).await;

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

async fn parse_magnet(argument: &str) -> Result<(), Box<dyn std::error::Error>> {
 let magnet_info = torrent::MagnetInfo::new(argument)?;

 println!("Tracker URL: {}", magnet_info.tracker_url);
 println!("Filename: {}", magnet_info.filename);
 println!("Info Hash: {}", magnet_info.info_hash);
 Ok(())
}

async fn magnet_handshake(argument: &str) -> Result<(), Box<dyn std::error::Error>> {
    let magnet_info = torrent::MagnetInfo::new(argument)?;
    let info_hash = magnet_info.info_hash;
    let request = tracker::TrackerRequest::magnet_request(magnet_info.tracker_url, info_hash.clone());
    let tracker_response = tracker::TrackerResponse::new(&*request.get_response()?)?;
    let handshake = transceive::Handshake::magnet_handshake(info_hash, request.peer_id);
    let peer = &tracker_response.peers[0];
    let mut response = [0u8; 68];
    let mut ext_handshake_length  = [0u8;4];
    
    let mut stream = tokio::net::TcpStream::connect(format!("{}:{}", peer.ip, peer.port)).await?;
    stream.write_all(&handshake.get()).await?;
    stream.read_exact(&mut response).await?;
    stream.write_all(&transceive::get_ext_handshake().await?).await?;

    stream.read_exact(&mut ext_handshake_length).await?;
    let mut length = u32::from_be_bytes(ext_handshake_length) as usize;

    let mut ext_handsake_response = vec![0u8; length];
    stream.read_exact(&mut ext_handsake_response).await?;

    if ext_handsake_response[0] != 20 {
        stream.read_exact(&mut ext_handshake_length).await?;
        length = u32::from_be_bytes(ext_handshake_length) as usize;
        
        ext_handsake_response = vec![0u8; length];
        stream.read_exact(&mut ext_handsake_response ).await?;
    }

    let payload = &ext_handsake_response[2..];
    let (peer_extensions, _) = file_utils::decode_bencoded_value(payload)?;

    println!("Peer ID: {}", hex::encode(&response[48..]));
    println!("Peer Metadata Extension ID: {}", peer_extensions["m"]["ut_metadata"]);
    Ok(())
}