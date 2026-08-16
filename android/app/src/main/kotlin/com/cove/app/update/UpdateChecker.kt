package com.cove.app.update

import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.HttpURLConnection
import java.net.URL
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.bouncycastle.util.encoders.Base64
import org.bouncycastle.util.encoders.DecoderException
import org.json.JSONObject

/** ROADMAP.md Фаза 18 — "механизм обновлений с проверкой подписи".
 * Android-аналог desktop/app/update_check.py — тот же протокол
 * (release-manifest.json + .sig в GitHub Releases, Ed25519), та же
 * граница ответственности: только уведомление + ссылка на страницу
 * релиза (по прямому запросу пользователя, см. коммит), не автозамена
 * APK — Android и не позволил бы это сделать тихо без
 * REQUEST_INSTALL_PACKAGES и системного диалога установки.
 *
 * Публичный ключ и протокол манифеста ДОЛЖНЫ совпадать с desktop-стороной
 * — это один и тот же релиз, подписанный одним и тем же ключом
 * (scripts/sign_release.py). */
object UpdateChecker {

    /** Версия ЭТОГО приложения — сравнивается с BuildConfig.VERSION_NAME
     * вызывающей стороной (SettingsScreen.kt), не хардкожена здесь, чтобы
     * не разъезжалась с build.gradle.kts. */

    // Публичный ключ (не секрет) — см. release-signing-key.pem.example.
    // Должен совпадать с RELEASE_PUBLIC_KEY_B64 в desktop/app/update_check.py.
    private const val RELEASE_PUBLIC_KEY_B64 = "OD0NGC0s4vSm5iAZyLuYsdlfRfcyWyHqX/qU2zAJRPw="

    // TODO: заполнить реальным "owner/repo" перед первым релизом
    // (репозиторий ещё не запушен на GitHub — см. ROADMAP.md Фаза 18).
    private const val GITHUB_REPO = "OWNER/REPO"

    private const val API_URL = "https://api.github.com/repos/$GITHUB_REPO/releases/latest"
    private const val CONNECT_TIMEOUT_MS = 10_000
    private const val READ_TIMEOUT_MS = 10_000

    data class UpdateResult(
        val updateAvailable: Boolean,
        val latestVersion: String,
        val releaseUrl: String,
    )

    class UpdateCheckException(message: String, cause: Throwable? = null) : Exception(message, cause)

    /** Кидает UpdateCheckException, если подпись не сошлась — не
     * возвращает Boolean специально, чтобы вызывающий код не мог случайно
     * проигнорировать false и продолжить работать с непроверенными
     * данными (симметрично Python-стороне).
     *
     * `publicKeyB64` — параметр, а не прямое чтение константы, специально
     * ради тестируемости: src/test/.../UpdateCheckerTest.kt подписывает
     * тестовыми ключами, сгенерированными на месте, и не может (не должно)
     * переопределить `RELEASE_PUBLIC_KEY_B64` — это `const val`, встроенная
     * в байткод, к тому же настоящий приватный ключ проекта
     * (release-signing-key.pem) в .gitignore и намеренно не должен
     * попадать даже в тестовый код. */
    @Throws(UpdateCheckException::class)
    fun verifyManifestSignature(
        manifestBytes: ByteArray,
        signatureB64: String,
        publicKeyB64: String = RELEASE_PUBLIC_KEY_B64,
    ) {
        // org.bouncycastle.util.encoders.Base64, не android.util.Base64:
        // тот же код тогда честно прогоняется в local unit test'ах на
        // чистой JVM (см. src/test/) без Robolectric — android.util.*
        // на голой JVM в unit-тестах — это метод-заглушка, кидающий
        // "Stub!" вместо реальной работы.
        val signature = try {
            Base64.decode(signatureB64.trim())
        } catch (e: DecoderException) {
            throw UpdateCheckException("подпись не в base64: ${e.message}", e)
        }
        val publicKeyBytes = Base64.decode(publicKeyB64)
        val publicKey = Ed25519PublicKeyParameters(publicKeyBytes, 0)

        val verifier = Ed25519Signer()
        verifier.init(false, publicKey)
        verifier.update(manifestBytes, 0, manifestBytes.size)
        if (!verifier.verifySignature(signature)) {
            throw UpdateCheckException(
                "подпись release-manifest.json не сошлась — файл мог быть подделан " +
                    "или скачан из скомпрометированного источника, не доверяем"
            )
        }
    }

    // internal, не private — доступны из src/test/ (UpdateCheckerTest.kt)
    // напрямую, без необходимости гонять их только через checkForUpdates()
    // (которая делает реальные HTTP-вызовы и не годится для unit-теста).
    internal fun parseVersion(v: String): List<Int> =
        try {
            v.split(".").map { it.toInt() }
        } catch (e: NumberFormatException) {
            throw UpdateCheckException("не удалось разобрать номер версии: $v", e)
        }

    internal fun compareVersions(a: List<Int>, b: List<Int>): Int {
        for (i in 0 until maxOf(a.size, b.size)) {
            val cmp = (a.getOrElse(i) { 0 }).compareTo(b.getOrElse(i) { 0 })
            if (cmp != 0) return cmp
        }
        return 0
    }

    private fun httpGetText(url: String): String {
        val conn = URL(url).openConnection() as HttpURLConnection
        conn.connectTimeout = CONNECT_TIMEOUT_MS
        conn.readTimeout = READ_TIMEOUT_MS
        conn.setRequestProperty("Accept", "application/vnd.github+json")
        try {
            if (conn.responseCode !in 200..299) {
                throw UpdateCheckException("GitHub API вернул ${conn.responseCode}")
            }
            return BufferedReader(InputStreamReader(conn.inputStream)).use { it.readText() }
        } catch (e: java.io.IOException) {
            throw UpdateCheckException("не удалось связаться с GitHub: ${e.message}", e)
        } finally {
            conn.disconnect()
        }
    }

    private fun httpGetBytes(url: String): ByteArray {
        val conn = URL(url).openConnection() as HttpURLConnection
        conn.connectTimeout = CONNECT_TIMEOUT_MS
        conn.readTimeout = READ_TIMEOUT_MS
        try {
            if (conn.responseCode !in 200..299) {
                throw UpdateCheckException("не удалось скачать $url: ${conn.responseCode}")
            }
            return conn.inputStream.use { it.readBytes() }
        } catch (e: java.io.IOException) {
            throw UpdateCheckException("не удалось скачать $url: ${e.message}", e)
        } finally {
            conn.disconnect()
        }
    }

    /** `currentVersion` передаётся вызывающей стороной
     * (`BuildConfig.VERSION_NAME`) — этот объект не знает о Gradle. */
    @Throws(UpdateCheckException::class)
    suspend fun checkForUpdates(currentVersion: String): UpdateResult = withContext(Dispatchers.IO) {
        val release = JSONObject(httpGetText(API_URL))
        val releaseUrl = if (release.has("html_url")) {
            release.getString("html_url")
        } else {
            "https://github.com/$GITHUB_REPO/releases/latest"
        }

        var manifestUrl: String? = null
        var sigUrl: String? = null
        val assets = release.optJSONArray("assets")
        if (assets != null) {
            for (i in 0 until assets.length()) {
                val asset = assets.getJSONObject(i)
                when (asset.optString("name")) {
                    "release-manifest.json" -> manifestUrl = asset.optString("browser_download_url")
                    "release-manifest.json.sig" -> sigUrl = asset.optString("browser_download_url")
                }
            }
        }
        if (manifestUrl == null || sigUrl == null) {
            throw UpdateCheckException(
                "в последнем релизе нет release-manifest.json/.sig — " +
                    "либо релиз собран без scripts/sign_release.py, либо ещё не опубликован"
            )
        }

        val manifestBytes = httpGetBytes(manifestUrl)
        val signatureB64 = String(httpGetBytes(sigUrl), Charsets.US_ASCII)

        verifyManifestSignature(manifestBytes, signatureB64)

        val manifest = JSONObject(String(manifestBytes, Charsets.UTF_8))
        val latestVersion = manifest.getString("version")

        UpdateResult(
            updateAvailable = compareVersions(parseVersion(latestVersion), parseVersion(currentVersion)) > 0,
            latestVersion = latestVersion,
            releaseUrl = releaseUrl,
        )
    }
}
