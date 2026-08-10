plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
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

    buildTypes {
        release {
            isMinifyEnabled = false
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
}
