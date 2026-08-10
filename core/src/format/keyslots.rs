//! FORMAT.md §3 — Keyslots region: пользователи и recovery-фраза как
//! единый механизм (recovery — это просто ещё один слот).

use crate::crypto::{aead, kdf, keys::WrappedDek};
use crate::error::{CoveError, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Admin,
    ReadWrite,
    ReadOnly,
}

impl Role {
    fn to_u8(self) -> u8 {
        match self {
            Role::Admin => 0,
            Role::ReadWrite => 1,
            Role::ReadOnly => 2,
        }
    }
    fn from_u8(v: u8) -> Result<Self> {
        match v {
            0 => Ok(Role::Admin),
            1 => Ok(Role::ReadWrite),
            2 => Ok(Role::ReadOnly),
            _ => Err(CoveError::FormatError {
                detail: format!("unknown role byte {v}"),
            }),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotType {
    User,
    Recovery,
}

impl SlotType {
    fn to_u8(self) -> u8 {
        match self {
            SlotType::User => 0,
            SlotType::Recovery => 1,
        }
    }
    fn from_u8(v: u8) -> Result<Self> {
        match v {
            0 => Ok(SlotType::User),
            1 => Ok(SlotType::Recovery),
            _ => Err(CoveError::FormatError {
                detail: format!("unknown slot_type byte {v}"),
            }),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Keyslot {
    pub slot_type: SlotType,
    pub username: String,
    pub role: Role,
    pub kdf_salt: [u8; kdf::SALT_LEN],
    pub kdf_params: kdf::KdfParams,
    pub wrapped_dek: WrappedDek,
}

const USERNAME_CAP: usize = 64;
const WRAPPED_CIPHERTEXT_LEN: usize = crate::crypto::keys::DEK_LEN + aead::TAG_LEN; // 48

pub const SLOT_LEN: usize = 1 // state
    + 1 // slot_type
    + 1 // role
    + 1 // username_len
    + USERNAME_CAP
    + kdf::SALT_LEN
    + 4 + 4 + 4 // kdf params
    + aead::NONCE_LEN
    + WRAPPED_CIPHERTEXT_LEN
    + 32; // slot checksum

pub const CAPACITY: usize = 16;

const STATE_EMPTY: u8 = 0;
const STATE_ACTIVE: u8 = 1;

/// Пустой слот на диске — используется при удалении пользователя
/// (точечная перезапись, см. container::Container::remove_user).
pub const EMPTY_SLOT: [u8; SLOT_LEN] = [0u8; SLOT_LEN];

pub(crate) fn serialize_slot(slot: &Keyslot) -> Result<[u8; SLOT_LEN]> {
    let uname = slot.username.as_bytes();
    if uname.len() > USERNAME_CAP {
        return Err(CoveError::FormatError {
            detail: "username too long for keyslot".into(),
        });
    }
    if slot.wrapped_dek.ciphertext.len() != WRAPPED_CIPHERTEXT_LEN {
        return Err(CoveError::FormatError {
            detail: "unexpected wrapped DEK length".into(),
        });
    }

    let mut buf = [0u8; SLOT_LEN];
    let mut pos = 0;
    buf[pos] = STATE_ACTIVE;
    pos += 1;
    buf[pos] = slot.slot_type.to_u8();
    pos += 1;
    buf[pos] = slot.role.to_u8();
    pos += 1;
    buf[pos] = uname.len() as u8;
    pos += 1;
    buf[pos..pos + uname.len()].copy_from_slice(uname);
    pos += USERNAME_CAP;
    buf[pos..pos + kdf::SALT_LEN].copy_from_slice(&slot.kdf_salt);
    pos += kdf::SALT_LEN;
    buf[pos..pos + 4].copy_from_slice(&slot.kdf_params.memory_kib.to_le_bytes());
    pos += 4;
    buf[pos..pos + 4].copy_from_slice(&slot.kdf_params.iterations.to_le_bytes());
    pos += 4;
    buf[pos..pos + 4].copy_from_slice(&slot.kdf_params.parallelism.to_le_bytes());
    pos += 4;
    buf[pos..pos + aead::NONCE_LEN].copy_from_slice(&slot.wrapped_dek.nonce);
    pos += aead::NONCE_LEN;
    buf[pos..pos + WRAPPED_CIPHERTEXT_LEN].copy_from_slice(&slot.wrapped_dek.ciphertext);
    pos += WRAPPED_CIPHERTEXT_LEN;

    let checksum = blake3::hash(&buf[0..pos]);
    buf[pos..pos + 32].copy_from_slice(&checksum.as_bytes()[..]);
    pos += 32;
    debug_assert_eq!(pos, SLOT_LEN);
    Ok(buf)
}

fn parse_slot(buf: &[u8; SLOT_LEN]) -> Result<Option<Keyslot>> {
    if buf[0] == STATE_EMPTY {
        return Ok(None);
    }
    let checksum_at = SLOT_LEN - 32;
    let expected = blake3::hash(&buf[0..checksum_at]);
    if expected.as_bytes()[..] != buf[checksum_at..SLOT_LEN] {
        return Err(CoveError::FormatError {
            detail: "keyslot checksum mismatch".into(),
        });
    }

    let mut pos = 1;
    let slot_type = SlotType::from_u8(buf[pos])?;
    pos += 1;
    let role = Role::from_u8(buf[pos])?;
    pos += 1;
    let uname_len = buf[pos] as usize;
    pos += 1;
    let username = String::from_utf8(buf[pos..pos + uname_len].to_vec())
        .map_err(|_| CoveError::FormatError {
            detail: "invalid utf8 username".into(),
        })?;
    pos += USERNAME_CAP;
    let kdf_salt: [u8; kdf::SALT_LEN] = buf[pos..pos + kdf::SALT_LEN].try_into().unwrap();
    pos += kdf::SALT_LEN;
    let memory_kib = u32::from_le_bytes(buf[pos..pos + 4].try_into().unwrap());
    pos += 4;
    let iterations = u32::from_le_bytes(buf[pos..pos + 4].try_into().unwrap());
    pos += 4;
    let parallelism = u32::from_le_bytes(buf[pos..pos + 4].try_into().unwrap());
    pos += 4;
    let nonce: [u8; aead::NONCE_LEN] = buf[pos..pos + aead::NONCE_LEN].try_into().unwrap();
    pos += aead::NONCE_LEN;
    let ciphertext = buf[pos..pos + WRAPPED_CIPHERTEXT_LEN].to_vec();

    Ok(Some(Keyslot {
        slot_type,
        username,
        role,
        kdf_salt,
        kdf_params: kdf::KdfParams {
            memory_kib,
            iterations,
            parallelism,
        },
        wrapped_dek: WrappedDek { ciphertext, nonce },
    }))
}

pub fn serialize_region(slots: &[Keyslot]) -> Result<Vec<u8>> {
    if slots.len() > CAPACITY {
        return Err(CoveError::FormatError {
            detail: "too many keyslots for capacity".into(),
        });
    }
    let mut out = Vec::with_capacity(SLOT_LEN * CAPACITY);
    for slot in slots {
        out.extend_from_slice(&serialize_slot(slot)?);
    }
    for _ in slots.len()..CAPACITY {
        out.extend_from_slice(&EMPTY_SLOT);
    }
    Ok(out)
}

/// Индексируемая раскладка (длина всегда `CAPACITY`, `None` — пустой слот).
/// Индекс — это и есть позиция слота на диске
/// (`header.keyslots_offset + i * SLOT_LEN`), нужна для точечной перезаписи
/// одного слота при add_user/remove_user/change_password.
pub fn parse_region(bytes: &[u8]) -> Result<Vec<Option<Keyslot>>> {
    if bytes.len() != SLOT_LEN * CAPACITY {
        return Err(CoveError::FormatError {
            detail: "keyslots region has unexpected size".into(),
        });
    }
    let mut out = Vec::with_capacity(CAPACITY);
    for chunk in bytes.chunks_exact(SLOT_LEN) {
        let arr: [u8; SLOT_LEN] = chunk.try_into().unwrap();
        out.push(parse_slot(&arr)?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keys::{wrap_dek, Dek};

    fn sample_slot(username: &str) -> Keyslot {
        let dek = Dek::generate();
        let salt = [3u8; kdf::SALT_LEN];
        let params = kdf::KdfParams::default();
        let kek = kdf::derive_kek(b"hunter2", &salt, params).unwrap();
        let wrapped = wrap_dek(&dek, &kek).unwrap();
        Keyslot {
            slot_type: SlotType::User,
            username: username.to_string(),
            role: Role::Admin,
            kdf_salt: salt,
            kdf_params: params,
            wrapped_dek: wrapped,
        }
    }

    #[test]
    fn region_roundtrip() {
        let slots = vec![sample_slot("admin"), sample_slot("guest")];
        let region = serialize_region(&slots).unwrap();
        assert_eq!(region.len(), SLOT_LEN * CAPACITY);
        let parsed = parse_region(&region).unwrap();
        assert_eq!(parsed.len(), CAPACITY);
        assert_eq!(parsed[0].as_ref().unwrap().username, "admin");
        assert_eq!(parsed[1].as_ref().unwrap().username, "guest");
        assert!(parsed[2].is_none());
    }

    #[test]
    fn empty_slots_ignored() {
        let region = serialize_region(&[]).unwrap();
        let parsed = parse_region(&region).unwrap();
        assert!(parsed.iter().all(|s| s.is_none()));
    }

    #[test]
    fn slot_corruption_detected() {
        let region = serialize_region(&[sample_slot("admin")]).unwrap();
        let mut corrupted = region;
        corrupted[10] ^= 0xFF;
        assert!(parse_region(&corrupted).is_err());
    }
}
