//! Фаза 17 (ROADMAP.md) — нагрузочный тест на ОДНОМ большом многоблочном
//! файле (в дополнение к Фазе 15, которая гоняла много мелких файлов).
//! Реальная проверка корректности (не только тайминги): контент детально
//! воспроизводим по формуле, поэтому сравниваем BLAKE3-хэш целиком после
//! round-trip'а и делаем точечные проверки byte-for-byte через read_at()
//! на границах блоков — не веря на слово, что "не упало" уже значит "верно".
//!
//! Запуск: `cargo run --release --example large_file_bench -- <size_mb>`
//! (по умолчанию 2048 МБ = 2 ГиБ).

use cove_core::container::{Container, LockedContainer};
use std::io::{Read, Write};
use std::time::Instant;

const PASSWORD: &str = "large file bench password 12345";

fn pattern_byte(pos: u64) -> u8 {
    (pos % 251) as u8
}

fn main() {
    let size_mb: u64 = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(2048);
    let size_bytes = size_mb * 1024 * 1024;
    println!("=== Cove Фаза 17 — большой файл, {size_mb} МБ ===");

    let tmp = std::env::temp_dir();
    let src_path = tmp.join(format!("cove_large_src_{}.bin", std::process::id()));
    let container_path = tmp.join(format!("cove_large_bench_{}.slr", std::process::id()));
    let dest_path = tmp.join(format!("cove_large_dest_{}.bin", std::process::id()));
    let _ = std::fs::remove_file(&container_path);

    print!("Генерация исходного файла... ");
    std::io::stdout().flush().unwrap();
    let t0 = Instant::now();
    let mut hasher = blake3::Hasher::new();
    {
        let mut f = std::fs::File::create(&src_path).unwrap();
        let chunk_size = 4 * 1024 * 1024;
        let mut buf = vec![0u8; chunk_size];
        let mut written = 0u64;
        while written < size_bytes {
            let this_chunk = chunk_size.min((size_bytes - written) as usize);
            for (i, b) in buf[..this_chunk].iter_mut().enumerate() {
                *b = pattern_byte(written + i as u64);
            }
            f.write_all(&buf[..this_chunk]).unwrap();
            hasher.update(&buf[..this_chunk]);
            written += this_chunk as u64;
        }
        f.sync_all().unwrap();
    }
    let expected_hash = hasher.finalize();
    println!("{:.3}s", t0.elapsed().as_secs_f64());

    let (mut container, _recovery) = Container::create(
        container_path.to_str().unwrap(),
        "admin",
        PASSWORD,
    )
    .unwrap();

    print!("import_file... ");
    std::io::stdout().flush().unwrap();
    let t0 = Instant::now();
    let file_id = container.import_file(src_path.to_str().unwrap(), 0).unwrap();
    println!("{:.3}s", t0.elapsed().as_secs_f64());

    print!("close() (commit)... ");
    std::io::stdout().flush().unwrap();
    let t0 = Instant::now();
    container.close().unwrap();
    println!("{:.3}s", t0.elapsed().as_secs_f64());

    print!("повторное открытие (unlock)... ");
    std::io::stdout().flush().unwrap();
    let t0 = Instant::now();
    let locked = LockedContainer::open(container_path.to_str().unwrap()).unwrap();
    let container = locked.unlock("admin", PASSWORD).unwrap();
    println!("{:.3}s", t0.elapsed().as_secs_f64());

    let size = container.file_size(file_id).unwrap();
    assert_eq!(size, size_bytes, "размер файла не совпадает после round-trip");

    print!("export_file (полное потоковое чтение)... ");
    std::io::stdout().flush().unwrap();
    let t0 = Instant::now();
    container.export_file(file_id, dest_path.to_str().unwrap()).unwrap();
    let export_elapsed = t0.elapsed();
    println!("{:.3}s", export_elapsed.as_secs_f64());

    print!("проверка BLAKE3-хэша экспортированного файла... ");
    std::io::stdout().flush().unwrap();
    let t0 = Instant::now();
    let mut out_hasher = blake3::Hasher::new();
    {
        let mut f = std::fs::File::open(&dest_path).unwrap();
        let mut buf = vec![0u8; 4 * 1024 * 1024];
        loop {
            let n = f.read(&mut buf).unwrap();
            if n == 0 {
                break;
            }
            out_hasher.update(&buf[..n]);
        }
    }
    let actual_hash = out_hasher.finalize();
    assert_eq!(actual_hash, expected_hash, "ХЭШ НЕ СОВПАДАЕТ — повреждение при round-trip!");
    println!("{:.3}s — СОВПАДАЕТ", t0.elapsed().as_secs_f64());

    // Точечные проверки read_at() на границах блоков (DEFAULT_BLOCK_SIZE =
    // 4МиБ) — там, где чаще всего живут off-by-one ошибки при склейке
    // соседних блоков.
    print!("точечные проверки read_at() на границах блоков... ");
    std::io::stdout().flush().unwrap();
    let block_size = 4u64 * 1024 * 1024;
    let mut checks = 0;
    let mut boundary = block_size;
    while boundary < size_bytes {
        let offset = boundary - 3;
        let len = 6u32;
        let data = container.read_at(file_id, offset, len).unwrap();
        let expected: Vec<u8> = (0..len as u64).map(|i| pattern_byte(offset + i)).collect();
        assert_eq!(data, expected, "read_at не совпадает на границе блока offset={offset}");
        checks += 1;
        boundary += block_size;
    }
    println!("{checks} границ, все совпали");

    container.close().unwrap();

    let _ = std::fs::remove_file(&src_path);
    let _ = std::fs::remove_file(&container_path);
    let _ = std::fs::remove_file(&dest_path);

    println!("=== Всё корректно ===");
}
