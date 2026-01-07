use anyhow::{anyhow, Result};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let out = hasher.finalize();
    hex::encode(out)
}

pub fn read_bytes(path: &Path) -> Result<Vec<u8>> {
    fs::read(path).map_err(|e| anyhow!("failed to read {}: {e}", path.display()))
}
