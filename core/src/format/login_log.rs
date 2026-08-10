//! Журнал входов (ROADMAP.md Фаза 4). Хранит только успешные разблокировки:
//! записать неудачную попытку было бы нечем шифровать — DEK на этот момент
//! ещё не получен. Учёт неудачных попыток/лимит попыток входа — отдельная
//! задача Фазы 12 (там же автоблокировка), не этого журнала.

use crate::crypto::{aead, keys};
use crate::error::{CoveError, Result};
use crate::format::wire::{push_string, push_u32, push_u64, push_u8, Reader};
use crate::users::LoginLogEntry;

/// Не даём журналу расти бесконечно — храним последние N входов.
pub const MAX_ENTRIES: usize = 1000;

fn encode_entry(e: &LoginLogEntry, buf: &mut Vec<u8>) {
    push_string(buf, &e.username);
    push_u64(buf, e.timestamp);
    push_u8(buf, e.success as u8);
}

fn decode_entry(r: &mut Reader) -> Result<LoginLogEntry> {
    let username = r.string()?;
    let timestamp = r.u64()?;
    let success = r.u8()? != 0;
    Ok(LoginLogEntry {
        username,
        timestamp,
        success,
    })
}

pub fn encode(entries: &[LoginLogEntry], dek: &keys::Dek) -> Vec<u8> {
    let trimmed = if entries.len() > MAX_ENTRIES {
        &entries[entries.len() - MAX_ENTRIES..]
    } else {
        entries
    };

    let mut plaintext = Vec::new();
    push_u32(&mut plaintext, trimmed.len() as u32);
    for e in trimmed {
        encode_entry(e, &mut plaintext);
    }

    let key = dek.subkey(keys::domain::LOGIN_LOG);
    let nonce = aead::random_nonce();
    let ciphertext = aead::seal(&key, &nonce, &plaintext).expect("seal never fails here");

    let mut blob = Vec::with_capacity(aead::NONCE_LEN + ciphertext.len());
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ciphertext);
    blob
}

pub fn decode(blob: &[u8], dek: &keys::Dek) -> Result<Vec<LoginLogEntry>> {
    if blob.len() < aead::NONCE_LEN {
        return Err(CoveError::FormatError {
            detail: "login log blob too short".into(),
        });
    }
    let nonce: [u8; aead::NONCE_LEN] = blob[0..aead::NONCE_LEN].try_into().unwrap();
    let key = dek.subkey(keys::domain::LOGIN_LOG);
    let plaintext = aead::open(&key, &nonce, &blob[aead::NONCE_LEN..])?;

    let mut r = Reader::new(&plaintext);
    let count = r.u32()? as usize;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        out.push(decode_entry(&mut r)?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::Dek;

    fn entry(username: &str, ts: u64) -> LoginLogEntry {
        LoginLogEntry {
            username: username.to_string(),
            timestamp: ts,
            success: true,
        }
    }

    #[test]
    fn roundtrip() {
        let dek = Dek::generate();
        let entries = vec![entry("admin", 100), entry("guest", 200)];
        let blob = encode(&entries, &dek);
        let decoded = decode(&blob, &dek).unwrap();
        assert_eq!(decoded, entries);
    }

    #[test]
    fn caps_to_max_entries() {
        let dek = Dek::generate();
        let entries: Vec<LoginLogEntry> = (0..(MAX_ENTRIES + 50) as u64)
            .map(|i| entry("admin", i))
            .collect();
        let blob = encode(&entries, &dek);
        let decoded = decode(&blob, &dek).unwrap();
        assert_eq!(decoded.len(), MAX_ENTRIES);
        // Оставлены самые свежие записи, а не первые.
        assert_eq!(decoded.last().unwrap().timestamp, entries.last().unwrap().timestamp);
    }
}
