//! FORMAT.md §6a — Commit Pointer, двойная буферизация для атомарности.

pub const COMMIT_POINTER_LEN: usize = 512;
const SELF_CHECKSUM_OFFSET: usize = 48;

#[derive(Debug, Clone, Copy)]
pub struct CommitPointer {
    pub version_counter: u64,
    pub superblock_offset: u64,
    /// BLAKE3 контрольная сумма зашифрованного Superblock-блоба на диске —
    /// проверяется ДО деривации ключа из пароля (FORMAT.md §6a).
    pub superblock_checksum: [u8; 32],
}

impl CommitPointer {
    pub fn serialize(&self) -> [u8; COMMIT_POINTER_LEN] {
        let mut buf = [0u8; COMMIT_POINTER_LEN];
        buf[0..8].copy_from_slice(&self.version_counter.to_le_bytes());
        buf[8..16].copy_from_slice(&self.superblock_offset.to_le_bytes());
        buf[16..48].copy_from_slice(&self.superblock_checksum);
        let self_checksum = blake3::hash(&buf[0..SELF_CHECKSUM_OFFSET]);
        buf[48..80].copy_from_slice(&self_checksum.as_bytes()[..]);
        buf
    }

    pub fn parse(buf: &[u8; COMMIT_POINTER_LEN]) -> Self {
        CommitPointer {
            version_counter: u64::from_le_bytes(buf[0..8].try_into().unwrap()),
            superblock_offset: u64::from_le_bytes(buf[8..16].try_into().unwrap()),
            superblock_checksum: buf[16..48].try_into().unwrap(),
        }
    }

    /// Структурная self-проверка без обращения к диску — защита от торна
    /// записи самого Commit Pointer. `version_counter == 0` значит "слот
    /// ещё не использовался", это тоже невалидно.
    pub fn self_check(buf: &[u8; COMMIT_POINTER_LEN]) -> bool {
        let version = u64::from_le_bytes(buf[0..8].try_into().unwrap());
        if version == 0 {
            return false;
        }
        let expected = blake3::hash(&buf[0..SELF_CHECKSUM_OFFSET]);
        expected.as_bytes()[..] == buf[48..80]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let cp = CommitPointer {
            version_counter: 3,
            superblock_offset: 12345,
            superblock_checksum: [7u8; 32],
        };
        let bytes = cp.serialize();
        assert!(CommitPointer::self_check(&bytes));
        let parsed = CommitPointer::parse(&bytes);
        assert_eq!(parsed.version_counter, 3);
        assert_eq!(parsed.superblock_offset, 12345);
    }

    #[test]
    fn zero_version_invalid() {
        let bytes = [0u8; COMMIT_POINTER_LEN];
        assert!(!CommitPointer::self_check(&bytes));
    }

    #[test]
    fn torn_write_detected() {
        let cp = CommitPointer {
            version_counter: 1,
            superblock_offset: 1,
            superblock_checksum: [1u8; 32],
        };
        let mut bytes = cp.serialize();
        bytes[10] ^= 0xFF; // портим superblock_offset уже после того как self_checksum посчитан
        assert!(!CommitPointer::self_check(&bytes));
    }
}
