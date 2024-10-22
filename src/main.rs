use std::{env, fs::{self, File}, io::{Read, Write}, net::TcpStream, path::{PathBuf, Path}};
use sha1::{Digest, Sha1};
use bittorrent_starter_rust::torrent;
use bittorrent_starter_rust::tracker;
use bittorrent_starter_rust::transceive;
use bittorrent_starter_rust::file_utils;

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
            let decoded_value = (file_utils::decode_bencoded_value(argument.as_bytes())?).0;
            println!("{}", serde_json::to_string(&decoded_value)?);
        },

        "info" => {
            let torrent = torrent::Torrent::new(PathBuf::from(argument))?;
            let info_hash = torrent.info_hash()?;
            
            println!("Tracker URL: {}", torrent.announce);
            println!("Length: {}", torrent.info.length);
            println!("Info Hash: {}", info_hash);
            println!("Piece Length: {}", torrent.info.piece_length);
            println!("Piece Hashes: {}", hex::encode(torrent.info.pieces));
        },

        "peers" => {
            let torrent = torrent::Torrent::new(PathBuf::from(argument))?;
            let info_hash = torrent.info_hash()?;
            let request = tracker::TrackerRequest::new(torrent.announce, info_hash, torrent.info.length);
            let response = request.get_response().unwrap();
            let tracker_info= tracker::TrackerResponse::new(&*response)?;

            for peer in tracker_info.peers {
                println!("{}:{}", peer.ip, peer.port);
            }
        },

        "handshake" => {
            let torrent = torrent::Torrent::new(PathBuf::from(argument))?;
            let client_id = "TestRTAAA11234567899".to_string();
            let handshake = transceive::Handshake::new(torrent.info_hash()?, client_id);
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

            let torrent = torrent::Torrent::new(PathBuf::from(&args[4]))?;
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
            let request = tracker::TrackerRequest::new(torrent.announce, info_hash, torrent.info.length);
            let response = request.get_response().unwrap();
            let tracker_info = tracker::TrackerResponse::new(&*response)?;
            let handshake = transceive::Handshake::new(info_hash_clone, client_id);
            let mut handshake_response = [0u8; 68];
            let peer = &tracker_info.peers[0];
            
            let mut stream = TcpStream::connect(format!("{}:{}",peer.ip, peer.port ))?;
            stream.write_all(&handshake.get())?;
            stream.read_exact(&mut handshake_response)?;
            let _bitfield = transceive::recieve_response(&mut stream)?;

            let mut block_offset: u32 = 0;
            let mut pending_requests: usize = 0;
            let mut blocks: Vec<(u32,Vec<u8>)> = Vec::new();
            let mut block_size: u32 = 16 * 1024;

            transceive::send_message("interested", &mut stream, piece_index, block_offset, block_size)?;
            let _unchoke = transceive::recieve_response(&mut stream)?;
            let mut block_index = 0;

            while block_offset < piece_length as u32 {
                if block_offset < piece_length as u32 && pending_requests < max_requests {
                    println!("Sending request");
                    transceive::send_message("request", &mut stream, piece_index, block_offset, block_size)?;
                    println!("{} offset of {} total", block_offset, piece_length);
                    block_offset += block_size;
                    pending_requests += 1;
                    block_index += 1;
                    block_size = file_utils::calc_block_size(piece_length, block_size, block_index);
                }

                match transceive::recieve_response(&mut stream)? {
                    Some((_received_piece_index, received_block_offset, block_data)) => {
                        println!("Received block");
                        blocks.push((received_block_offset, block_data));
                        pending_requests -= 1;
                    }
                    None => {}
                }
            }
            

            let full_piece = file_utils::join_blocks(blocks, piece_length as u32);
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

            let torrent = torrent::Torrent::new(PathBuf::from(&args[4]))?;
            let total_file_length = torrent.info.length.clone() as u32;
            let total_pieces = (total_file_length as f64 / torrent.info.piece_length.clone() as f64).ceil() as u32;
            
            let torrent_clone = torrent.clone();
            let info_hash = torrent.info_hash()?;
            let info_hash_clone = info_hash.clone();
            let client_id = "TestRTAAA11234567899".to_string();
            let request = tracker::TrackerRequest::new(torrent.announce, info_hash, torrent.info.length);
            let response = request.get_response().unwrap();
            let tracker_info = tracker::TrackerResponse::new(&*response)?;
            let handshake = transceive::Handshake::new(info_hash_clone, client_id);
            let mut handshake_response = [0u8; 68];
            let peer = &tracker_info.peers[0];
            
            let mut stream = TcpStream::connect(format!("{}:{}",peer.ip, peer.port ))?;
            stream.write_all(&handshake.get())?;
            stream.read_exact(&mut handshake_response)?;
            let _bitfield = transceive::recieve_response(&mut stream)?;
            let mut pieces: Vec<(u32,Vec<u8>)> = Vec::new();
            transceive::send_message("interested", &mut stream, &0, 0, 0)?;
            let _unchoke = transceive::recieve_response(&mut stream)?;

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
                        transceive::send_message("request", &mut stream, &piece_index, block_offset, block_size)?;
                        println!("{} offset of {} total", block_offset, piece_length);
                        block_offset += block_size;
                        pending_requests += 1;
                        block_index += 1;
                        block_size = file_utils::calc_block_size(piece_length, block_size, block_index);
                    }
    
                    match transceive::recieve_response(&mut stream)? {
                        Some((_received_piece_index, received_block_offset, block_data)) => {
                            println!("Received block");
                            blocks.push((received_block_offset, block_data));
                            pending_requests -= 1;
                        }
                        None => {}
                    }
                }

                let full_piece = file_utils::join_blocks(blocks, piece_length as u32);
                let mut hasher = Sha1::new();
                hasher.update(&full_piece);
                let full_piece_hash = hex::encode(hasher.finalize());
    
                if torrent_clone.validate_piece(&piece_index, full_piece_hash) {
                    pieces.push((piece_length, full_piece));
                } else {
                    eprintln!("Recieved piece does not match hash data");
                }
            }
            let full_file = file_utils::join_pieces(pieces, total_file_length);
            file.write_all(&full_file)?;
        } 

        _ => eprintln!("Unknown command: {}", command),
    }

    Ok(())
}
