#![no_main]
use cove_core::format::keyslots;
use libfuzzer_sys::fuzz_target;

// parse_region — читается сразу после Header, тоже до деривации ключа
// (список username'ов нужен ДО ввода пароля, чтобы показать форму входа).
fuzz_target!(|data: &[u8]| {
    let _ = keyslots::parse_region(data);
});
