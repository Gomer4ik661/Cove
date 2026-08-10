//! FORMAT.md §2 — Header (512 байт, plaintext).

use crate::error::{CoveError, Result};

pub const MAGIC: &[u8; 8] = b"COVEfmt\0";
pub const HEADER_LEN: usize = 512;
const CHECKSUM_LEN: usize = 32;
const CHECKSUM_OFFSET: usize = HEADER_LEN - CHECKSUM_LEN; // 480

#[derive(Debug, Clone, Copy)]
pub struct Header {
    pub format_version: u16,
    pub container_uuid: [u8; 16],
    pub created_at: u64,
    pub block_size: u32,
    pub keyslots_offset: u64,
    pub keyslots_len: u64,
    pub commit_a_offset: u64,
    pub commit_b_offset: u64,
}

impl Header {
    pub fn serialize(&self) -> [u8; HEADER_LEN] {
        let mut buf = [0u8; HEADER_LEN];
        buf[0..8].copy_from_slice(MAGIC);
        buf[8..10].copy_from_slice(&self.format_version.to_le_bytes());
        buf[10..26].copy_from_slice(&self.container_uuid);
        buf[26..34].copy_from_slice(&self.created_at.to_le_bytes());
        buf[34..38].copy_from_slice(&self.block_size.to_le_bytes());
        buf[38..46].copy_from_slice(&self.keyslots_offset.to_le_bytes());
        buf[46..54].copy_from_slice(&self.keyslots_len.to_le_bytes());
        buf[54..62].copy_from_slice(&self.commit_a_offset.to_le_bytes());
        buf[62..70].copy_from_slice(&self.commit_b_offset.to_le_bytes());
        // [70..CHECKSUM_OFFSET) остаётся зарезервированным нулевым паддингом.
        let checksum = blake3::hash(&buf[0..CHECKSUM_OFFSET]);
        buf[CHECKSUM_OFFSET..HEADER_LEN].copy_from_slice(&checksum.as_bytes()[..]);
        buf
    }

    pub fn parse(buf: &[u8; HEADER_LEN]) -> Result<Self> {
        if &buf[0..8] != MAGIC {
            return Err(CoveError::FormatError {
                detail: "bad magic bytes — not a .slr container".into(),
            });
        }
        let expected = blake3::hash(&buf[0..CHECKSUM_OFFSET]);
        if expected.as_bytes()[..] != buf[CHECKSUM_OFFSET..HEADER_LEN] {
            return Err(CoveError::FormatError {
                detail: "header checksum mismatch — corrupted container".into(),
            });
        }
        Ok(Header {
            format_version: u16::from_le_bytes(buf[8..10].try_into().unwrap()),
            container_uuid: buf[10..26].try_into().unwrap(),
            created_at: u64::from_le_bytes(buf[26..34].try_into().unwrap()),
            block_size: u32::from_le_bytes(buf[34..38].try_into().unwrap()),
            keyslots_offset: u64::from_le_bytes(buf[38..46].try_into().unwrap()),
            keyslots_len: u64::from_le_bytes(buf[46..54].try_into().unwrap()),
            commit_a_offset: u64::from_le_bytes(buf[54..62].try_into().unwrap()),
            commit_b_offset: u64::from_le_bytes(buf[62..70].try_into().unwrap()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Header {
        Header {
            format_version: 1,
            container_uuid: [9u8; 16],
            created_at: 1_700_000_000,
            block_size: 4 * 1024 * 1024,
            keyslots_offset: 512,
            keyslots_len: 3456,
            commit_a_offset: 512 + 3456,
            commit_b_offset: 512 + 3456 + 512,
        }
    }

    #[test]
    fn roundtrip() {
        let h = sample();
        let bytes = h.serialize();
        let parsed = Header::parse(&bytes).unwrap();
        assert_eq!(parsed.format_version, h.format_version);
        assert_eq!(parsed.container_uuid, h.container_uuid);
        assert_eq!(parsed.keyslots_offset, h.keyslots_offset);
        assert_eq!(parsed.commit_b_offset, h.commit_b_offset);
    }

    #[test]
    fn corruption_detected() {
        let h = sample();
        let mut bytes = h.serialize();
        bytes[20] ^= 0xFF;
        assert!(Header::parse(&bytes).is_err());
    }

    #[test]
    fn bad_magic_rejected() {
        let mut bytes = sample().serialize();
        bytes[0] = b'X';
        assert!(Header::parse(&bytes).is_err());
    }
}
