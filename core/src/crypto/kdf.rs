//! Argon2id KDF — оборачивает пароль пользователя в KEK.
//! См. FORMAT.md §3 и docs/FORMAT.md §10 (выбор крейта).

use crate::error::{CoveError, Result};
use argon2::{Algorithm, Argon2, Params, Version};

pub const SALT_LEN: usize = 32;
pub const KEK_LEN: usize = 32;

#[derive(Debug, Clone, Copy)]
pub struct KdfParams {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        // Отправная точка (OWASP-минимум для Argon2id), НЕ финальные
        // production-параметры — те бенчмаркаются под целевое железо в
        // Фазе 3 (ROADMAP.md), в т.ч. под слабые Android-устройства.
        Self {
            memory_kib: 19 * 1024,
            iterations: 2,
            parallelism: 1,
        }
    }
}

pub fn derive_kek(
    password: &[u8],
    salt: &[u8; SALT_LEN],
    params: KdfParams,
) -> Result<[u8; KEK_LEN]> {
    let argon2_params = Params::new(
        params.memory_kib,
        params.iterations,
        params.parallelism,
        Some(KEK_LEN),
    )
    .map_err(|e| CoveError::FormatError {
        detail: format!("invalid argon2 params: {e}"),
    })?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params);

    let mut out = [0u8; KEK_LEN];
    argon2
        .hash_password_into(password, salt, &mut out)
        .map_err(|e| CoveError::FormatError {
            detail: format!("argon2id failed: {e}"),
        })?;
    Ok(out)
}
