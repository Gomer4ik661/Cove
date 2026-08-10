//! Состояние разблокированной сессии. DEK живёт только здесь и обнуляется
//! при Drop (zeroize) — THREAT_MODEL.md §2.3.

use crate::crypto::keys::Dek;

pub struct Session {
    pub(crate) dek: Dek,
}
