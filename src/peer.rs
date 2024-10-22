use serde::{Deserialize, Serialize};
use core::str;

#[allow(dead_code)]
#[derive(Debug, Serialize, Deserialize)]
pub struct PeerData {
    pub ip: String,
    pub port: u16,
}