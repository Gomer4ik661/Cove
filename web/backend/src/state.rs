//! Общее состояние сервера: карта активных сессий и счётчики попыток входа
//! для rate-limiting. THREAT_MODEL.md §2.4 — web backend наименее доверенный
//! процесс, поэтому и то, и другое живёт только в памяти процесса, ничего
//! не персистится на диск отдельно от самого `.slr`-контейнера.

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use rand::RngCore;

use crate::actor::Command;

/// Сессия неактивна дольше этого — считаем её истёкшей при следующем запросе.
pub const SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(30 * 60);
/// Не больше стольки неудачных попыток входа с одного IP...
pub const LOGIN_MAX_ATTEMPTS: u32 = 10;
/// ...за это окно времени.
pub const LOGIN_WINDOW: Duration = Duration::from_secs(15 * 60);

pub struct Session {
    /// Канал к потоку-актору, владеющему `Container` этой сессии (actor.rs).
    /// `std::sync::mpsc::Sender::send` не блокирует (канал неограничен),
    /// так что вызывать его прямо из async-хендлера безопасно.
    pub tx: std::sync::mpsc::Sender<Command>,
    pub csrf_token: String,
    pub username: String,
    pub role: String,
    pub last_activity: Instant,
}

struct LoginWindow {
    count: u32,
    window_start: Instant,
}

pub struct AppState {
    pub container_path: PathBuf,
    /// Обслуживается ли сервер по HTTPS — определяет `Secure`-флаг сессионной
    /// куки (без него браузер не отправил бы её обратно по чистому HTTP).
    pub https: bool,
    pub sessions: Mutex<HashMap<String, Session>>,
    login_attempts: Mutex<HashMap<IpAddr, LoginWindow>>,
}

impl AppState {
    pub fn new(container_path: PathBuf, https: bool) -> Self {
        AppState {
            container_path,
            https,
            sessions: Mutex::new(HashMap::new()),
            login_attempts: Mutex::new(HashMap::new()),
        }
    }

    /// `true`, если этому IP сейчас можно пробовать логиниться дальше.
    pub fn check_login_rate_limit(&self, ip: IpAddr) -> bool {
        let mut map = self.login_attempts.lock().unwrap();
        let now = Instant::now();
        let entry = map.entry(ip).or_insert(LoginWindow {
            count: 0,
            window_start: now,
        });
        if now.duration_since(entry.window_start) > LOGIN_WINDOW {
            entry.count = 0;
            entry.window_start = now;
        }
        entry.count < LOGIN_MAX_ATTEMPTS
    }

    pub fn record_login_failure(&self, ip: IpAddr) {
        let mut map = self.login_attempts.lock().unwrap();
        let now = Instant::now();
        let entry = map.entry(ip).or_insert(LoginWindow {
            count: 0,
            window_start: now,
        });
        if now.duration_since(entry.window_start) > LOGIN_WINDOW {
            entry.count = 0;
            entry.window_start = now;
        }
        entry.count += 1;
    }

    pub fn record_login_success(&self, ip: IpAddr) {
        self.login_attempts.lock().unwrap().remove(&ip);
    }

    /// Возвращает сессию по id, обновляя `last_activity`, либо `None` если
    /// сессия неизвестна или истекла по бездействию (и в этом случае сразу
    /// вычищает её и просит актор корректно закрыть контейнер).
    pub fn touch_session(&self, session_id: &str) -> Option<(String, String, String)> {
        let mut sessions = self.sessions.lock().unwrap();
        let expired = {
            let s = sessions.get(session_id)?;
            s.last_activity.elapsed() > SESSION_IDLE_TIMEOUT
        };
        if expired {
            if let Some(s) = sessions.remove(session_id) {
                let _ = s.tx.send(Command::Shutdown {
                    reply: tokio::sync::oneshot::channel().0,
                });
            }
            return None;
        }
        let s = sessions.get_mut(session_id).unwrap();
        s.last_activity = Instant::now();
        Some((s.csrf_token.clone(), s.username.clone(), s.role.clone()))
    }
}

pub fn random_token() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, bytes)
}
