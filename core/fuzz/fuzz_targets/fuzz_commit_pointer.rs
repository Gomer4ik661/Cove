#![no_main]
use cove_core::format::commit::{CommitPointer, COMMIT_POINTER_LEN};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < COMMIT_POINTER_LEN {
        return;
    }
    let buf: [u8; COMMIT_POINTER_LEN] = data[0..COMMIT_POINTER_LEN].try_into().unwrap();
    if CommitPointer::self_check(&buf) {
        let _ = CommitPointer::parse(&buf);
    }
});
