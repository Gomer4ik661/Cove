//! FORMAT.md §9 — учёт свободных слотов в Data Blocks region.
//! Пока плоский список свободных `block_index`; полноценная
//! компактификация — Фаза 15.

use crate::crypto::{aead, keys};
use crate::error::{CoveError, Result};
use crate::format::wire::{push_u32, push_u64, Reader};

pub fn encode(free_blocks: &[u64], dek: &keys::Dek) -> Vec<u8> {
    let mut plaintext = Vec::with_capacity(4 + free_blocks.len() * 8);
    push_u32(&mut plaintext, free_blocks.len() as u32);
    for b in free_blocks {
        push_u64(&mut plaintext, *b);
    }

    let key = dek.subkey(keys::domain::FREE_MAP);
    let nonce = aead::random_nonce();
    let ciphertext = aead::seal(&key, &nonce, &plaintext).expect("seal never fails here");

    let mut blob = Vec::with_capacity(aead::NONCE_LEN + ciphertext.len());
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ciphertext);
    blob
}

pub fn decode(blob: &[u8], dek: &keys::Dek) -> Result<Vec<u64>> {
    if blob.len() < aead::NONCE_LEN {
        return Err(CoveError::FormatError {
            detail: "free block map blob too short".into(),
        });
    }
    let nonce: [u8; aead::NONCE_LEN] = blob[0..aead::NONCE_LEN].try_into().unwrap();
    let key = dek.subkey(keys::domain::FREE_MAP);
    let plaintext = aead::open(&key, &nonce, &blob[aead::NONCE_LEN..])?;

    let mut r = Reader::new(&plaintext);
    let count = r.u32()? as usize;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        out.push(r.u64()?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::Dek;

    #[test]
    fn roundtrip() {
        let dek = Dek::generate();
        let blob = encode(&[1, 2, 3], &dek);
        let decoded = decode(&blob, &dek).unwrap();
        assert_eq!(decoded, vec![1, 2, 3]);
    }

    #[test]
    fn empty_roundtrip() {
        let dek = Dek::generate();
        let blob = encode(&[], &dek);
        let decoded = decode(&blob, &dek).unwrap();
        assert!(decoded.is_empty());
    }
}
