use serde_json;
use std::env;

// Available if you need it!
// use serde_bencode

#[allow(dead_code)]
fn decode_bencoded_value(encoded_value: &str) -> serde_json::Value {
    let ident = encoded_value.chars().next().unwrap();

    if ident.is_digit(10) {
        // Example: "5:hello" -> "hello"
        let colon_index = encoded_value.find(':').unwrap();
        let number_string = &encoded_value[..colon_index];
        let number = number_string.parse::<i64>().unwrap();
        let string = &encoded_value[colon_index + 1..colon_index + 1 + number as usize];
        return serde_json::Value::String(string.to_string());
    } else if ident == 'i' {
        let e_index = encoded_value.find('e').unwrap();
        let number_string = &encoded_value[1..e_index];
        let number = number_string.parse::<i64>().unwrap();
        return serde_json::Value::Number(serde_json::Number::from(number));
    } else if ident == 'l' {
        let mut list = Vec::new();
        let mut rest = &encoded_value[1..];
        while rest.chars().next().unwrap() != 'e' {
            let item = decode_bencoded_value(rest);
            let colon_index = rest.find(':').unwrap_or_else(|| rest.find('e').unwrap());
            rest = &rest[colon_index..];
            list.push(item);

        }
        return serde_json::Value::Array(list);
    } else {
        panic!("Unhandled encoded value: {}", encoded_value)
    }
}

// Usage: your_bittorrent.sh decode "<encoded_value>"
fn main() {
    let args: Vec<String> = env::args().collect();
    let command = &args[1];

    if command == "decode" {
        let encoded_value = &args[2];
        let decoded_value = decode_bencoded_value(encoded_value);
        println!("{}", decoded_value.to_string());
    } else {
        println!("unknown command: {}", args[1])
    }
}
