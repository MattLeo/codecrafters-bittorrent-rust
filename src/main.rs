use serde_json;
use std::env;

fn decode_bencoded_value(encoded_value: &str) -> serde_json::Value {
    let ident = encoded_value.chars().next().unwrap();

    if ident.is_digit(10) {
        let colon_index = encoded_value.find(':').unwrap();
        let number = encoded_value[..colon_index].parse::<usize>().unwrap();
        let string = &encoded_value[colon_index + 1..colon_index + 1 + number];
        serde_json::Value::String(string.to_string())
    } else if ident == 'i' {
        let e_index = encoded_value.find('e').unwrap();
        let number = encoded_value[1..e_index].parse::<i64>().unwrap();
        serde_json::Value::Number(serde_json::Number::from(number))
    } else if ident == 'l' {
        let mut list = Vec::new();
        let mut rest = &encoded_value[1..];
        while rest.chars().next().unwrap() != 'e' {
            let item = decode_bencoded_value(rest);
            let length = match &item {
                serde_json::Value::String(s) => s.len() + rest.find(':').unwrap() + 1,
                serde_json::Value::Number(_) => rest.find('e').unwrap() + 1,
                serde_json::Value::Array(_) => rest.find('e').unwrap() + 1,
                _ => panic!("Unhandled value type"),
            };
            list.push(item);
            rest = &rest[length..];
        }
        serde_json::Value::Array(list)
    } else {
        panic!("Unhandled encoded value: {}", encoded_value);
    }
}

// Usage: your_bittorrent.sh decode "<encoded_value>"
fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: {} decode <encoded_value>", args[0]);
        return;
    }
    let command = &args[1];

    if command == "decode" {
        let encoded_value = &args[2];
        let decoded_value = decode_bencoded_value(encoded_value);
        println!("{}", decoded_value);
    } else {
        eprintln!("unknown command: {}", command);
    }
}