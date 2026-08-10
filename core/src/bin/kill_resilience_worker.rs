//! Фаза 17 (ROADMAP.md) — вспомогательный процесс для теста устойчивости
//! к `kill -9` посреди записи (core/tests/kill_resilience.rs). Не тест сам
//! по себе — запускается тестом как подпроцесс и убивается им же.
//!
//! Сценарий: создаёт контейнер, коммитит (версия 1, заведомо валидна),
//! затем добавляет вторую пачку файлов и печатает маркер прямо перед
//! ВТОРЫМ close() — родительский процесс убивает этот worker сразу после
//! маркера, стараясь попасть в середину записи commit'а.

use cove_core::container::Container;
use std::io::Write;

fn main() {
    let path = std::env::args().nth(1).expect("usage: kill_resilience_worker <path>");

    let (mut container, _recovery) =
        Container::create(&path, "admin", "kill test password 12345").unwrap();
    for i in 0..200 {
        container
            .import_file_from_bytes(&format!("first_{i}.txt"), 0, b"first batch content")
            .unwrap();
    }
    container.close().unwrap(); // версия 1 — базовая, заведомо валидная точка отсчёта

    let locked = cove_core::container::LockedContainer::open(&path).unwrap();
    let mut container = locked.unlock("admin", "kill test password 12345").unwrap();
    // Вторая, более крупная пачка — чтобы запись commit'а (free_map +
    // file_table + login_log + superblock + переключение указателя) заняла
    // измеримое время и родитель имел реальный шанс убить процесс
    // непосредственно в середине этой последовательности записей.
    for i in 0..5000 {
        container
            .import_file_from_bytes(&format!("second_{i}.txt"), 0, b"second batch content, a bit longer to pad the file table")
            .unwrap();
    }

    println!("ABOUT_TO_CLOSE");
    std::io::stdout().flush().unwrap();

    container.close().unwrap();
    println!("CLOSE_OK");
    std::io::stdout().flush().unwrap();
}
