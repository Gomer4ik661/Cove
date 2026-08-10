import java.util.Properties

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

// Фаза 16 (ROADMAP.md) — реальная подпись release-сборок настоящим
// keystore. Файл с паролями не в git (.gitignore) — см.
// android/keystore.properties.example для формата. Без него release-сборка
// собирается неподписанной (сработает только через CI secrets — см.
// .github/workflows/release.yml), но НЕ падает — иначе обычный
// `assembleDebug`/`cargo test`-стиль CI-джобы без доступа к секретам
// ломались бы на конфигурации, которая им не нужна.
val keystorePropertiesFile = rootProject.file("keystore.properties")
val keystoreProperties = Properties()
if (keystorePropertiesFile.exists()) {
    keystoreProperties.load(keystorePropertiesFile.inputStream())
}

android {
    namespace = "com.cove.app"
    compileSdk = 36

    defaultConfig {
        applicationId = "com.cove.app"
        // minSdk = 24 — совпадает с уровнем API, под который слинкован
        // libcove_core_uniffi.so (см. bindings/android/.cargo/../.cargo/config.toml
        // в корне репозитория — линкеры aarch64-linux-android24-clang и т.д.)
        minSdk = 24
        targetSdk = 36
        versionCode = 1
        versionName = "0.1.0"
    }

    signingConfigs {
        if (keystorePropertiesFile.exists()) {
            create("release") {
                storeFile = rootProject.file(keystoreProperties.getProperty("storeFile"))
                storePassword = keystoreProperties.getProperty("storePassword")
                keyAlias = keystoreProperties.getProperty("keyAlias")
                keyPassword = keystoreProperties.getProperty("keyPassword")
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            if (keystorePropertiesFile.exists()) {
                signingConfig = signingConfigs.getByName("release")
            }
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    buildFeatures {
        compose = true
    }

    // Собранные под Android .so из bindings/android (Фаза 14, ROADMAP.md)
    // складываются сюда вручную скриптом scripts/build_android_bindings.sh —
    // не через Cargo-плагин Gradle, чтобы не тащить лишнюю Gradle-магию
    // поверх и без того рабочего `cargo build --target ...`.
    sourceSets {
        getByName("main") {
            jniLibs.srcDirs("src/main/jniLibs")
        }
    }
}

dependencies {
    implementation("androidx.core:core-ktx:1.15.0")
    implementation("androidx.activity:activity-compose:1.9.3")
    implementation(platform("androidx.compose:compose-bom:2024.12.01"))
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-graphics")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.7")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.9.0")
    implementation("androidx.biometric:biometric:1.1.0")
    implementation("androidx.security:security-crypto:1.1.0-alpha06")
    // FragmentActivity — androidx.biometric.BiometricPrompt требует именно его.
    implementation("androidx.fragment:fragment-ktx:1.8.5")

    // UniFFI-сгенерированные Kotlin-биндинги (bindings/android/generated/)
    // используют JNA для вызова cdylib напрямую, без JNI-обёрток вручную.
    // 5.17+ — libjnidispatch.so в 5.15 был выровнен под 4KB-страницы,
    // что триггерило PageSizeMismatchDialog на 16KB-эмуляторах/устройствах.
    implementation("net.java.dev.jna:jna:5.17.0@aar")

    // media3 — видео/аудио-плеер поверх кастомного DataSource
    // (media/ContainerDataSource.kt), стримящего байты через
    // container.readAt() без временных расшифрованных файлов на диске —
    // Android-аналог desktop ContainerFileDevice (ROADMAP.md Фаза 14,
    // доработка после того как обнаружился пробел с просмотрщиками).
    implementation("androidx.media3:media3-exoplayer:1.5.1")
    implementation("androidx.media3:media3-ui:1.5.1")
}
