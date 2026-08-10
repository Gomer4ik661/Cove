//! Логин/логаут и извлечение аутентифицированной сессии из запроса.
//! THREAT_MODEL.md §2.4: rate-limit брутфорса, uniform auth-ошибка (не
//! раскрываем, неверный логин или пароль), CSRF-токен на все меняющие
//! состояние запросы, HttpOnly + SameSite=Strict сессионная кука.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{ConnectInfo, FromRequestParts, State};
use axum::http::{request::Parts, Method, StatusCode};
use axum::Json;
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use cove_core::LockedContainer;
use serde::{Deserialize, Serialize};

use crate::actor::{self, Command};
use crate::error::ApiError;
use crate::state::{random_token, AppState, Session};

pub const SESSION_COOKIE: &str = "cove_session";

#[derive(Deserialize)]
pub struct LoginRequest {
    username: String,
    password: String,
}

#[derive(Serialize)]
pub struct LoginResponse {
    username: String,
    role: String,
    csrf_token: String,
}

pub async fn login(
    State(state): State<Arc<AppState>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    jar: CookieJar,
    Json(body): Json<LoginRequest>,
) -> Result<(CookieJar, Json<LoginResponse>), ApiError> {
    let ip = addr.ip();
    if !state.check_login_rate_limit(ip) {
        return Err(ApiError::RateLimited);
    }

    let path = state
        .container_path
        .to_str()
        .ok_or_else(|| ApiError::BadRequest("invalid container path".into()))?;
    let locked = LockedContainer::open(path).map_err(ApiError::Core)?;

    let container = match locked.unlock(&body.username, &body.password) {
        Ok(c) => c,
        Err(e) => {
            if matches!(e.category(), cove_core::error::ErrorCategory::AuthFailed) {
                state.record_login_failure(ip);
            }
            return Err(ApiError::Core(e));
        }
    };
    state.record_login_success(ip);

    let username = container.current_username().to_string();
    let role = format!("{:?}", container.current_role());
    let tx = actor::spawn(container);

    let session_id = random_token();
    let csrf_token = random_token();
    state.sessions.lock().unwrap().insert(
        session_id.clone(),
        Session {
            tx,
            csrf_token: csrf_token.clone(),
            username: username.clone(),
            role: role.clone(),
            last_activity: std::time::Instant::now(),
        },
    );

    let cookie = Cookie::build((SESSION_COOKIE, session_id))
        .http_only(true)
        .same_site(SameSite::Strict)
        .secure(state.https)
        .path("/")
        .build();

    Ok((
        jar.add(cookie),
        Json(LoginResponse {
            username,
            role,
            csrf_token,
        }),
    ))
}

pub async fn logout(
    State(state): State<Arc<AppState>>,
    jar: CookieJar,
) -> Result<(CookieJar, StatusCode), ApiError> {
    if let Some(cookie) = jar.get(SESSION_COOKIE) {
        if let Some(session) = state.sessions.lock().unwrap().remove(cookie.value()) {
            let (reply_tx, _reply_rx) = tokio::sync::oneshot::channel();
            let _ = session.tx.send(Command::Shutdown { reply: reply_tx });
        }
    }
    let removal = Cookie::build(SESSION_COOKIE).path("/").build();
    Ok((jar.remove(removal), StatusCode::NO_CONTENT))
}

/// Экстрактор, дающий хендлеру доступ к каналу актора текущей сессии.
/// Заодно проверяет CSRF-токен (заголовок `X-CSRF-Token`) для всех методов
/// кроме GET/HEAD — так каждый меняющий состояние хендлер получает защиту
/// просто через сигнатуру, без ручных проверок внутри.
pub struct AuthedSession {
    pub tx: std::sync::mpsc::Sender<Command>,
    #[allow(dead_code)]
    pub username: String,
    #[allow(dead_code)]
    pub role: String,
}

impl FromRequestParts<Arc<AppState>> for AuthedSession {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &Arc<AppState>,
    ) -> Result<Self, Self::Rejection> {
        let jar = CookieJar::from_headers(&parts.headers);
        let session_id = jar
            .get(SESSION_COOKIE)
            .map(|c| c.value().to_string())
            .ok_or(ApiError::Unauthorized)?;

        let (csrf_token, username, role) =
            state.touch_session(&session_id).ok_or(ApiError::Unauthorized)?;

        if parts.method != Method::GET && parts.method != Method::HEAD {
            let header_token = parts
                .headers
                .get("x-csrf-token")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            if header_token.is_empty() || header_token != csrf_token {
                return Err(ApiError::Forbidden);
            }
        }

        let tx = {
            let sessions = state.sessions.lock().unwrap();
            sessions
                .get(&session_id)
                .ok_or(ApiError::Unauthorized)?
                .tx
                .clone()
        };

        Ok(AuthedSession { tx, username, role })
    }
}
