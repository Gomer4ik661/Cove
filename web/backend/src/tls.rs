//! Самоподписанный TLS-сертификат для LAN (THREAT_MODEL.md §2.4: "HTTPS с
//! самоподписанным сертификатом... браузер честно предупредит пользователя,
//! это ожидаемо и объясняется в UI"). Сертификат генерируется один раз и
//! кешируется на диске — иначе он менялся бы при каждом перезапуске сервера
//! и предупреждение браузера/недоверие к отпечатку возникало бы заново
//! каждый раз, что хуже для UX, чем один раз принятое исключение.

use std::fs;
use std::net::IpAddr;
use std::path::PathBuf;

pub struct CertPaths {
    pub cert_pem: PathBuf,
    pub key_pem: PathBuf,
}

pub fn default_data_dir() -> PathBuf {
    dirs::data_dir()
        .unwrap_or_else(std::env::temp_dir)
        .join("cove")
}

pub fn cert_paths(data_dir: &std::path::Path) -> CertPaths {
    CertPaths {
        cert_pem: data_dir.join("web-cert.pem"),
        key_pem: data_dir.join("web-key.pem"),
    }
}

/// Загружает существующий сертификат с диска или генерирует новый
/// самоподписанный (SAN: localhost + 127.0.0.1, плюс переданные LAN-адреса).
pub fn load_or_generate(data_dir: &std::path::Path, extra_ips: &[IpAddr]) -> CertPaths {
    let paths = cert_paths(data_dir);
    if paths.cert_pem.exists() && paths.key_pem.exists() {
        tracing::info!(path = %paths.cert_pem.display(), "используем существующий TLS-сертификат");
        return paths;
    }

    fs::create_dir_all(data_dir).expect("не удалось создать каталог данных для сертификата");

    let mut san: Vec<String> = vec!["localhost".to_string(), "127.0.0.1".to_string()];
    for ip in extra_ips {
        san.push(ip.to_string());
    }

    let generated = rcgen::generate_simple_self_signed(san).expect("не удалось сгенерировать самоподписанный сертификат");
    fs::write(&paths.cert_pem, generated.cert.pem()).expect("не удалось записать cert.pem");
    fs::write(&paths.key_pem, generated.key_pair.serialize_pem()).expect("не удалось записать key.pem");
    tracing::info!(path = %paths.cert_pem.display(), "сгенерирован новый самоподписанный TLS-сертификат");
    paths
}
