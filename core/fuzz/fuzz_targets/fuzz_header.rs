#![no_main]
use cove_core::format::header::{Header, HEADER_LEN};
use libfuzzer_sys::fuzz_target;

// Header — единственная plaintext-структура в формате, разбирается до
// какой-либо криптографии. Цель: недоверенные байты (в т.ч. специально
// сфабрикованные, а не только случайно повреждённые) не должны приводить
// к панике/аборту при парсинге.
fuzz_target!(|data: &[u8]| {
    if data.len() < HEADER_LEN {
        return;
    }
    let buf: [u8; HEADER_LEN] = data[0..HEADER_LEN].try_into().unwrap();
    let _ = Header::parse(&buf);
});
