//! Фаза 15 (ROADMAP.md) — реальный замер производительности на большой
//! библиотеке. Не unit-тест: печатает тайминги на stdout, сравнение
//! baseline/после-оптимизаций делается вручную между запусками.
//!
//! Запуск (обязательно --release — в debug крипто-примитивы искажают
//! картину на порядки): `cargo run --release --example large_library_bench
//! -- 100000`. Второй аргумент (опционально) — сколько файлов, по
//! умолчанию 100000.

use cove_core::container::Container;
use std::time::Instant;

fn main() {
    let count: usize = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(100_000);

    let path = std::env::temp_dir().join(format!("cove_bench_{}.slr", std::process::id()));
    let path_str = path.to_str().unwrap();
    let _ = std::fs::remove_file(&path);

    println!("=== Cove Фаза 15 — бенчмарк на {count} файлах ===");

    let (mut container, _recovery) =
        Container::create(path_str, "admin", "bench password 12345").unwrap();

    let content = vec![0xABu8; 512]; // маленький файл — метаданные, не I/O содержимого, в фокусе
    let t0 = Instant::now();
    for i in 0..count {
        let name = format!("file_{i:07}.txt");
        container
            .import_file_from_bytes(&name, 0, &content)
            .unwrap();
    }
    let import_elapsed = t0.elapsed();
    println!(
        "Импорт {count} файлов: {:.3}s ({:.3}ms/файл)",
        import_elapsed.as_secs_f64(),
        import_elapsed.as_secs_f64() * 1000.0 / count as f64
    );

    let t0 = Instant::now();
    container.close().unwrap();
    let close_elapsed = t0.elapsed();
    println!("close() (commit File Table): {:.3}s", close_elapsed.as_secs_f64());

    let t0 = Instant::now();
    let locked = cove_core::container::LockedContainer::open(path_str).unwrap();
    let unlocked = locked.unlock("admin", "bench password 12345").unwrap();
    let unlock_elapsed = t0.elapsed();
    println!(
        "Повторное открытие (unlock, включая decode File Table): {:.3}s",
        unlock_elapsed.as_secs_f64()
    );

    let t0 = Instant::now();
    let listed = unlocked.list_dir(0).unwrap();
    let list_elapsed = t0.elapsed();
    println!(
        "list_dir(root) — {} записей: {:.3}s",
        listed.len(),
        list_elapsed.as_secs_f64()
    );

    let query = cove_core::search::SearchQuery {
        extension: Some("txt".to_string()),
        ..Default::default()
    };
    let t0 = Instant::now();
    let found = unlocked.search(query).unwrap();
    let search_elapsed = t0.elapsed();
    println!(
        "search(extension=txt) — {} совпадений: {:.3}s",
        found.len(),
        search_elapsed.as_secs_f64()
    );

    unlocked.close().unwrap();
    let _ = std::fs::remove_file(&path);
}
