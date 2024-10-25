use serde_json::Value;
use core::str;

#[allow(dead_code)]
pub fn decode_bencoded_value(encoded_value: &[u8]) -> Result<(Value, usize), Box<dyn std::error::Error>> {
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

#[allow(dead_code)]
pub fn calc_block_size(piece_len: u32, block_size: u32, block_index: u32) -> u32 {
    let full_blocks = piece_len / block_size;
    let last_block = piece_len % block_size;

    if block_index < full_blocks {
        block_size
    } else {
        last_block
    }
}

#[allow(dead_code)]
pub fn join_blocks(blocks: Vec<(u32, Vec<u8>)>, piece_length: u32) -> Vec<u8> {
    let mut piece_buffer = vec![0u8; piece_length as usize];
    for (block_offset, block_data) in blocks {
        let offset = block_offset as usize;
        let end = offset + block_data.len();
        piece_buffer[offset..end].copy_from_slice(&block_data);
    }

    piece_buffer
}

#[allow(dead_code)]
pub fn join_pieces(pieces: Vec<(u32, Vec<u8>)>, file_length: u32) -> Vec<u8> {
    let mut file_buffer = vec![0u8; file_length as usize];
    let mut current_offset = 0;
    for (_piece_offset, piece_data) in pieces {
        let start = current_offset as usize;
        let end = start + piece_data.len() as usize;
        file_buffer[start..end].copy_from_slice(&piece_data);
        current_offset = end;
    }
    file_buffer
}

#[allow(dead_code)]
pub fn split_header_and_data(message: &[u8]) -> Option<(&[u8], &[u8])> {
    if let Some(pos) = message.windows(2).position(|window| window == b"ee") {
        Some((&message[..pos + 2], &message[pos + 2..]))
    } else {
        None
    }
}