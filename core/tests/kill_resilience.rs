//! Фаза 17 (ROADMAP.md) — реальный тест устойчивости к `kill -9` посреди
//! записи commit'а. Не мок: реальный подпроцесс (src/bin/kill_resilience_worker.rs)
//! реально убивается сигналом SIGKILL в множестве прогонов с разными
//! микрозадержками относительно начала второго close(), стараясь застать
//! запись free_map/file_table/login_log/superblock/commit pointer в разгаре.
//! Инвариант (FORMAT.md §6a, атомарность через двойную буферизацию Commit
//! Pointer): контейнер обязан оставаться открываемым и содержать ЛИБО
//! полностью старую, ЛИБО полностью новую версию — никогда не что-то
//! среднее и никогда не паниковать/отказываться открываться.
#![cfg(unix)]

use cove_core::container::LockedContainer;
use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::time::Duration;

const PASSWORD: &str = "kill test password 12345";

#[test]
fn kill_minus_9_mid_commit_leaves_container_openable() {
    let worker = env!("CARGO_BIN_EXE_kill_resilience_worker");

    // Разные микрозадержки относительно момента "вот-вот начнётся commit" —
    // увеличивает шанс реально попасть серией прогонов в середину записи,
    // а не только до/после неё.
    let delays_micros: &[u64] = &[
        0, 1, 5, 20, 50, 100, 300, 800, 900, 1000, 1100, 1200, 1300, 1400, 1500, 1600, 1700,
        1800, 1900, 2000, 5000,
    ];

    for (trial, &delay) in delays_micros.iter().enumerate() {
        let path = std::env::temp_dir()
            .join(format!("cove_kill_test_{}_{trial}.slr", std::process::id()));
        let path_str = path.to_str().unwrap().to_string();
        let _ = std::fs::remove_file(&path);

        let mut child = Command::new(worker)
            .arg(&path_str)
            .stdout(Stdio::piped())
            .spawn()
            .expect("failed to spawn kill_resilience_worker");

        let stdout = child.stdout.take().unwrap();
        let mut reader = BufReader::new(stdout);
        let mut line = String::new();
        loop {
            line.clear();
            let n = reader.read_line(&mut line).unwrap_or(0);
            if n == 0 {
                break; // процесс завершился сам (см. обработку ниже) до маркера
            }
            if line.trim() == "ABOUT_TO_CLOSE" {
                break;
            }
        }

        if delay > 0 {
            std::thread::sleep(Duration::from_micros(delay));
        }
        let _ = child.kill(); // SIGKILL на Unix — то же самое, что kill -9
        let _ = child.wait();

        // Инвариант: контейнер должен оставаться открываемым и
        // разблокируемым независимо от того, куда именно попал kill.
        let locked = LockedContainer::open(&path_str).unwrap_or_else(|e| {
            panic!("trial {trial} (delay={delay}us): контейнер не открывается после kill -9: {e}")
        });
        let unlocked = locked.unlock("admin", PASSWORD).unwrap_or_else(|e| {
            panic!("trial {trial} (delay={delay}us): unlock не удался после kill -9: {e}")
        });
        let entries = unlocked
            .list_dir(0)
            .unwrap_or_else(|e| panic!("trial {trial} (delay={delay}us): list_dir паникует/падает: {e}"));

        // Единственные два легитимных исхода: старая версия (200, из
        // первого close()) или полностью новая (5200, второй close()
        // успел завершиться до kill) — ничего среднего быть не может.
        assert!(
            entries.len() == 200 || entries.len() == 5200,
            "trial {trial} (delay={delay}us): неожиданное число записей {} — похоже на порванный commit",
            entries.len()
        );
        unlocked.close().unwrap();

        let _ = std::fs::remove_file(&path);
    }
}
