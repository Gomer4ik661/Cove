//! Web-бэкенд (Фаза 13, ROADMAP.md). Зависит от cove-core НАПРЯМУЮ (Rust-to-
//! Rust, без FFI) — ARCHITECTURE.md §1. Один процесс обслуживает ОДИН
//! `.slr`-контейнер, путь к которому передаётся при запуске: сервер сам
//! никогда не расшифровывает контейнер сам по себе, только по запросу
//! `/api/login` с валидными учётными данными пользователя контейнера
//! (ARCHITECTURE.md §4 — Container живёт в актор-потоке конкретной сессии,
//! не в состоянии сервера).
//!
//! По умолчанию слушает HTTPS с самоподписанным сертификатом
//! (THREAT_MODEL.md §2.4). `--http` включает обычный HTTP — предполагается
//! только для локальной разработки или когда TLS терминируется отдельным
//! реверс-прокси, не для использования как есть в LAN.

mod actor;
mod auth;
mod error;
mod routes;
mod state;
mod tls;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use axum::extract::DefaultBodyLimit;
use axum::http::{header, HeaderValue};
use axum::routing::{delete, get, patch, post};
use axum::Router;
use clap::Parser;
use tower_http::services::ServeDir;
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::trace::TraceLayer;

use state::AppState;

#[derive(Parser)]
#[command(name = "cove-web-backend")]
struct Args {
    /// Путь к .slr-контейнеру, который обслуживает этот процесс.
    #[arg(long)]
    container: PathBuf,

    /// Адрес и порт для прослушивания.
    #[arg(long, default_value = "0.0.0.0:8443")]
    bind: SocketAddr,

    /// Отключить HTTPS и слушать обычный HTTP. Только для разработки или
    /// когда TLS уже терминирован реверс-прокси перед этим процессом.
    #[arg(long, default_value_t = false)]
    http: bool,

    /// Каталог для кеша самоподписанного TLS-сертификата.
    #[arg(long)]
    data_dir: Option<PathBuf>,

    /// Каталог со статикой фронтенда (index.html и т.д.).
    #[arg(long)]
    frontend_dir: Option<PathBuf>,
}

async fn health() -> &'static str {
    "ok"
}

/// Axum по умолчанию режет тело запроса на 2 МиБ (DefaultBodyLimit) — этого
/// достаточно для JSON-ручек, но `/api/upload` рассчитан на реальные
/// пользовательские файлы, включая видео, которые почти всегда больше.
/// Найдено вживую: загрузка файла >2 МиБ падала с "failed to read file
/// field" — тело обрывалось на лимите, а не файл был как-то повреждён.
/// 4 ГиБ — практический потолок, не архитектурный: `import_file_from_bytes`
/// держит файл целиком в памяти (multipart-байты → `Vec<u8>` → канал в
/// session-актор), в отличие от потокового `import_file` у Desktop/Android
/// (ROADMAP.md Фаза 7/14) — так что стриминг из браузера сюда пока не
/// заведён, а не забыт по невнимательности.
///
/// На 32-битных таргетах (найдено при кросс-компиляции под armv7/i686
/// Android — ROADMAP.md, "веб-морда в Android") `4 * 1024³` ровно на 1 байт
/// превышает `usize::MAX` (2^32 − 1) и не компилируется — но даже если бы
/// компилировалось, держать в памяти 4 ГиБ на 32-битном адресном
/// пространстве (а тем более в куче Android-процесса, обычно ограниченной
/// сотнями МиБ без `largeHeap`) нереалистично в принципе. Предел ниже там
/// честно отражает эту реальность, а не просто обходит переполнение.
const MAX_UPLOAD_BYTES: usize = if usize::BITS >= 64 {
    4 * 1024 * 1024 * 1024
} else {
    1024 * 1024 * 1024
};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    if !args.container.exists() {
        eprintln!(
            "контейнер не найден: {} (используйте --container <путь к .slr>)",
            args.container.display()
        );
        std::process::exit(1);
    }

    let state = Arc::new(AppState::new(args.container.clone(), !args.http));

    let frontend_dir = args
        .frontend_dir
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../frontend"));

    let api = Router::new()
        .route("/health", get(health))
        .route("/api/login", post(auth::login))
        .route("/api/logout", post(auth::logout))
        .route("/api/me", get(routes::me))
        .route("/api/library", get(routes::list_dir))
        .route("/api/trash", get(routes::list_trash))
        .route("/api/search", get(routes::search))
        .route("/api/folders", post(routes::create_folder))
        .route(
            "/api/upload",
            post(routes::upload).layer(DefaultBodyLimit::max(MAX_UPLOAD_BYTES)),
        )
        .route("/api/files/{id}/download", get(routes::download))
        .route("/api/files/{id}", delete(routes::delete))
        .route("/api/files/{id}/restore", post(routes::restore))
        .route("/api/files/{id}/rename", patch(routes::rename))
        .route("/api/files/{id}/move", patch(routes::move_file))
        .route("/api/files/{id}/favorite", patch(routes::set_favorite))
        .with_state(state)
        .layer(TraceLayer::new_for_http());

    let app = if frontend_dir.exists() {
        api.fallback_service(ServeDir::new(&frontend_dir))
    } else {
        tracing::warn!(
            path = %frontend_dir.display(),
            "каталог фронтенда не найден, отдаём только /api/*"
        );
        api
    };

    // no-cache (не no-store) — браузер вправе держать копию, но обязан
    // ревалидировать через If-Modified-Since на каждый запрос, не показывать
    // старую версию молча. Без этого правки app.js/style.css/index.html не
    // подхватывались обычным F5 — нашлось вживую несколько раз при живой
    // проверке этой же фазы (залипшая модалка, "логин не работает" — оба
    // раза деле было в закэшированной старой статике, не в самом коде).
    let app = app.layer(SetResponseHeaderLayer::overriding(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-cache"),
    ));

    let app = app.into_make_service_with_connect_info::<SocketAddr>();

    if args.http {
        tracing::warn!("HTTPS отключён (--http): используйте только для разработки или за TLS-терминирующим прокси");
        let listener = tokio::net::TcpListener::bind(args.bind)
            .await
            .unwrap_or_else(|e| panic!("не удалось слушать {}: {e}", args.bind));
        tracing::info!(addr = %args.bind, "cove web backend слушает HTTP");
        axum::serve(listener, app).await.expect("server error");
    } else {
        let data_dir = args.data_dir.unwrap_or_else(tls::default_data_dir);
        let extra_ip = match args.bind.ip() {
            ip if !ip.is_unspecified() => vec![ip],
            _ => vec![],
        };
        let paths = tls::load_or_generate(&data_dir, &extra_ip);
        let config = axum_server::tls_rustls::RustlsConfig::from_pem_file(&paths.cert_pem, &paths.key_pem)
            .await
            .expect("не удалось загрузить TLS-сертификат");
        tracing::info!(addr = %args.bind, "cove web backend слушает HTTPS (самоподписанный сертификат)");
        axum_server::bind_rustls(args.bind, config)
            .serve(app)
            .await
            .expect("server error");
    }
}
