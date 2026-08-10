#![no_main]
use cove_core::crypto::keys::Dek;
use cove_core::format::file_table::decode_file_table;
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

// Реальный ключ не нужен — decode_file_table должен либо честно
// провалить AEAD-аутентификацию, либо (для внешнего framing вроде
// page_count, который AEAD не покрывает — см. Фазу 17) отклонить
// неправдоподобные значения до аллокации. Ни то, ни другое не должно
// приводить к панике/аборту.
static DEK: OnceLock<Dek> = OnceLock::new();

fuzz_target!(|data: &[u8]| {
    let dek = DEK.get_or_init(Dek::generate);
    let _ = decode_file_table(data, dek);
});
