# Cove

Кроссплатформенное зашифрованное файловое хранилище — свой формат
контейнера (`.slr`), собственное Rust-ядро, три GUI (Desktop, Android,
Web) поверх одного и того же криптографического движка.

> **Статус: разработка, до релиза v1.0.** Публичный независимый
> security-аудит крипто-части ещё не проведён (см. [ROADMAP.md](ROADMAP.md#фаза-18-релиз-v10)
> и [docs/SECURITY_SELF_REVIEW.md](docs/SECURITY_SELF_REVIEW.md)) — не
> используйте для данных, утечка которых представляет реальный риск, до
> появления такого аудита.

## Что это

- Один файл `.slr` — зашифрованный контейнер: содержимое файлов, имена,
  структура папок и почти все метаданные зашифрованы (см.
  [docs/FORMAT.md](docs/FORMAT.md)).
- Envelope encryption: Argon2id (пароль → KEK) → XChaCha20-Poly1305 (KEK
  оборачивает DEK, DEK шифрует данные). Recovery-фраза (BIP39) как
  запасной путь разблокировки, независимый от пароля.
- Несколько пользователей с ролями внутри одного контейнера, журнал
  входов, лимит попыток.
- Библиотека с папками, избранным, поиском, разделами по типу файла
  (Фото/Видео/Документы/Музыка), миниатюрами, просмотром без расшифровки
  на диск.
- Три клиента поверх одного Core: Desktop (PySide6), Android (Jetpack
  Compose), встроенный Web-интерфейс (по умолчанию выключен).

Подробнее — [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) (как устроен
код) и [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) (от чего Cove
защищает, а от чего осознанно нет).

## Быстрый старт

### Desktop (Linux/Windows)

Готовые сборки — на странице [Releases](../../releases) (Linux:
AppImage или голый бинарник, Windows: `.exe`, пока не подписан).

Собрать из исходников:

```bash
./scripts/build_python_bindings.sh   # cove-python (Rust) → desktop/cove_core_py.so
cd desktop
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python main.py
```

Для AppImage: `./scripts/build_appimage.sh` (требует `rsvg-convert`).

### Android

Готовый APK — на странице [Releases](../../releases) (подписан
release-ключом).

Собрать из исходников (требует Android NDK — путь настраивается в
`.cargo/config.toml`, JDK 17, rustup-таргеты под все 4 ABI):

```bash
./scripts/build_android_bindings.sh   # cove-android (Rust) → UniFFI-биндинги + .so под все ABI
cd android
./gradlew assembleDebug
```

### Web-интерфейс

Встроен в Desktop-настройки (вкладка Web) или запускается отдельно:

```bash
cargo run -p cove-web-backend --release -- --container /путь/к/хранилищу.slr
```

По умолчанию слушает HTTPS с самоподписанным сертификатом на
`0.0.0.0:8443`. Выключен по умолчанию в Desktop-приложении — самая
широкая поверхность атаки в проекте (см. THREAT_MODEL.md §2.4),
включается явно администратором.

## Разработка

```bash
cargo test --workspace          # Core + все bindings
cargo test -p cove-core         # только Core
```

Fuzzing парсера контейнера, тест устойчивости к `kill -9`, нагрузочные
тесты — `core/fuzz/` и `core/examples/`, описаны в
[ROADMAP.md](ROADMAP.md#фаза-17-тестирование).

## Документация

| Файл | О чём |
|---|---|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Структура workspace, границы Core/bindings/GUI |
| [docs/FORMAT.md](docs/FORMAT.md) | Бинарный формат `.slr`: header, keyslots, File Table, блоки данных |
| [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) | Модель угроз: что защищаем, от кого, и что осознанно не обещаем |
| [docs/USER_GUIDE.md](docs/USER_GUIDE.md) | Пользовательская инструкция |
| [docs/SECURITY_SELF_REVIEW.md](docs/SECURITY_SELF_REVIEW.md) | Внутреннее саморевью крипто-части — **не замена независимому аудиту** |
| [ROADMAP.md](ROADMAP.md) | История разработки по фазам, что сделано и что осталось |

## Лицензия

[AGPL-3.0-or-later](LICENSE). Использование Cove как основы для
сетевого сервиса (в том числе Web-интерфейса) требует раскрытия
исходного кода пользователям такого сервиса — см. текст лицензии.
