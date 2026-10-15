//! Крошечные помощники для ручной бинарной (де)сериализации — общие для
//! нескольких модулей format::*, чтобы не дублировать push/read логику.

use crate::error::{CoveError, Result};

pub fn push_u8(buf: &mut Vec<u8>, v: u8) {
    buf.push(v);
}
pub fn push_u16(buf: &mut Vec<u8>, v: u16) {
    buf.extend_from_slice(&v.to_le_bytes());
}
pub fn push_u32(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_le_bytes());
}
pub fn push_u64(buf: &mut Vec<u8>, v: u64) {
    buf.extend_from_slice(&v.to_le_bytes());
}
pub fn push_bytes(buf: &mut Vec<u8>, v: &[u8]) {
    buf.extend_from_slice(v);
}
pub fn push_string(buf: &mut Vec<u8>, s: &str) {
    let bytes = s.as_bytes();
    push_u16(buf, bytes.len() as u16);
    push_bytes(buf, bytes);
}

pub struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.pos + n > self.bytes.len() {
            return Err(CoveError::FormatError {
                detail: "unexpected end of buffer while parsing".into(),
            });
        }
        let s = &self.bytes[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    pub fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    pub fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    pub fn bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        self.take(n)
    }
    pub fn string(&mut self) -> Result<String> {
        let len = u16::from_le_bytes(self.take(2)?.try_into().unwrap()) as usize;
        let raw = self.take(len)?;
        String::from_utf8(raw.to_vec()).map_err(|_| CoveError::FormatError {
            detail: "invalid utf8 string in container".into(),
        })
    }

    /// Байт, оставшихся непрочитанными до конца буфера — используется там,
    /// где формат неоднозначен без версии (file_table.rs: обратная
    /// совместимость с записями, созданными до появления `folder_category`)
    /// и корректность разбора проверяется по факту "дочитали ровно до
    /// конца", а не по отдельному полю версии.
    pub fn remaining(&self) -> usize {
        self.bytes.len() - self.pos
    }
}
