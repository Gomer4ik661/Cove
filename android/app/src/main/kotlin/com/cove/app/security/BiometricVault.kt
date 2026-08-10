package com.cove.app.security

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import android.util.Base64
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Биометрия как альтернатива паролю (ROADMAP.md Фаза 14) — НЕ хранит DEK
 * или ключевой материал контейнера напрямую. Core принимает только
 * username+password для unlock(), так что здесь под замком лежит сам
 * пароль пользователя, зашифрованный ключом из Android Keystore с
 * `setUserAuthenticationRequired(true)` — ключ физически не отдаст
 * содержимое без свежего успешного прохождения биометрии/PIN на
 * аппаратном уровне (TEE/StrongBox), это не полагается на секретность
 * файла на диске. Зашифрованный блок дополнительно лежит в
 * EncryptedSharedPreferences (defense in depth, не единственная линия
 * защиты).
 *
 * Компромисс тот же, что у Signal/Bitwarden и подобных: если ОС устройства
 * скомпрометирована на уровне root/эквивалента, это не даёт дополнительной
 * защиты сверх обычного пароля — но останавливает обычное чтение с диска
 * и требует реального прохождения биометрии для расшифровки на
 * нескомпрометированном устройстве.
 */
class BiometricVault(context: Context) {
    private val appContext = context.applicationContext

    private val prefs by lazy {
        val masterKey = MasterKey.Builder(appContext)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()
        EncryptedSharedPreferences.create(
            appContext,
            "cove_biometric_vault",
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
        )
    }

    fun isBiometricAvailable(): Boolean {
        val manager = BiometricManager.from(appContext)
        return manager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG) ==
            BiometricManager.BIOMETRIC_SUCCESS
    }

    fun hasSavedCredentials(path: String): Boolean {
        return prefs.contains(keyFor(path, "username")) && prefs.contains(keyFor(path, "password"))
    }

    fun forget(path: String) {
        prefs.edit()
            .remove(keyFor(path, "username"))
            .remove(keyFor(path, "password"))
            .remove(keyFor(path, "iv"))
            .apply()
        runCatching { keyStore().deleteEntry(keyAlias(path)) }
    }

    /**
     * Шифрует и сохраняет пароль — но сначала обязательно просит пройти
     * биометрию: ключ создан с `setUserAuthenticationRequired(true)`, а это
     * требует свежую аутентификацию не только на расшифровку, но и на само
     * шифрование при первом включении (реальная ошибка, найденная вживую —
     * `IllegalBlockSizeException` при попытке шифровать без прохождения
     * BiometricPrompt: Keystore отклоняет операцию без auth-подтверждения).
     */
    fun enroll(
        activity: FragmentActivity,
        path: String,
        username: String,
        password: String,
        onSuccess: () -> Unit,
        onError: (String) -> Unit,
    ) {
        val cipher: Cipher
        try {
            val secretKey = getOrCreateKey(path)
            cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.ENCRYPT_MODE, secretKey)
        } catch (e: Exception) {
            onError("Не удалось подготовить ключ биометрии: ${e.message}")
            return
        }

        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Включить вход по биометрии")
            .setSubtitle("Подтвердите личность, чтобы сохранить доступ")
            .setNegativeButtonText("Отмена")
            .build()

        val prompt = BiometricPrompt(
            activity,
            ContextCompat.getMainExecutor(activity),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    val resultCipher = result.cryptoObject?.cipher ?: run {
                        onError("Внутренняя ошибка биометрии")
                        return
                    }
                    try {
                        val encrypted = resultCipher.doFinal(password.toByteArray(Charsets.UTF_8))
                        prefs.edit()
                            .putString(keyFor(path, "username"), username)
                            .putString(keyFor(path, "password"), Base64.encodeToString(encrypted, Base64.NO_WRAP))
                            .putString(keyFor(path, "iv"), Base64.encodeToString(resultCipher.iv, Base64.NO_WRAP))
                            .apply()
                        onSuccess()
                    } catch (e: Exception) {
                        onError("Не удалось сохранить пароль: ${e.message}")
                    }
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    onError(errString.toString())
                }
            },
        )
        prompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(cipher))
    }

    /**
     * Показывает системный BiometricPrompt; при успехе расшифровывает
     * сохранённый пароль и возвращает его через [onSuccess]. Если ключ
     * стал недействителен (например пользователь добавил новый отпечаток —
     * Android аннулирует привязанные к биометрии ключи), тихо забывает
     * сохранённые данные и просит войти паролем заново.
     */
    fun authenticate(
        activity: FragmentActivity,
        path: String,
        onSuccess: (username: String, password: String) -> Unit,
        onError: (String) -> Unit,
        onCancel: () -> Unit,
    ) {
        val username = prefs.getString(keyFor(path, "username"), null)
        val ivB64 = prefs.getString(keyFor(path, "iv"), null)
        val encryptedB64 = prefs.getString(keyFor(path, "password"), null)
        if (username == null || ivB64 == null || encryptedB64 == null) {
            onError("Нет сохранённых данных для входа по биометрии")
            return
        }

        val cipher: Cipher
        try {
            val secretKey = getExistingKey(path) ?: run {
                forget(path)
                onError("Биометрический ключ недействителен, войдите паролем")
                return
            }
            cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.DECRYPT_MODE, secretKey, GCMParameterSpec(128, Base64.decode(ivB64, Base64.NO_WRAP)))
        } catch (e: KeyPermanentlyInvalidatedException) {
            forget(path)
            onError("Биометрия устройства изменилась, войдите паролем ещё раз")
            return
        }

        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Вход в Cove")
            .setSubtitle("Подтвердите личность, чтобы разблокировать хранилище")
            .setNegativeButtonText("Отмена")
            .build()

        val prompt = BiometricPrompt(
            activity,
            ContextCompat.getMainExecutor(activity),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    val resultCipher = result.cryptoObject?.cipher ?: run {
                        onError("Внутренняя ошибка биометрии")
                        return
                    }
                    try {
                        val decrypted = resultCipher.doFinal(Base64.decode(encryptedB64, Base64.NO_WRAP))
                        onSuccess(username, String(decrypted, Charsets.UTF_8))
                    } catch (e: Exception) {
                        onError("Не удалось расшифровать сохранённый пароль: ${e.message}")
                    }
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    if (errorCode == BiometricPrompt.ERROR_NEGATIVE_BUTTON || errorCode == BiometricPrompt.ERROR_USER_CANCELED) {
                        onCancel()
                    } else {
                        onError(errString.toString())
                    }
                }
            },
        )
        prompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(cipher))
    }

    private fun keyStore(): KeyStore = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }

    private fun keyAlias(path: String) = "cove_biometric_${path.hashCode()}"

    private fun keyFor(path: String, field: String) = "${path.hashCode()}_$field"

    private fun getExistingKey(path: String): SecretKey? {
        val ks = keyStore()
        return ks.getKey(keyAlias(path), null) as? SecretKey
    }

    private fun getOrCreateKey(path: String): SecretKey {
        getExistingKey(path)?.let { return it }
        val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE_PROVIDER)
        val spec = KeyGenParameterSpec.Builder(
            keyAlias(path),
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setUserAuthenticationRequired(true)
            .setInvalidatedByBiometricEnrollment(true)
            .build()
        keyGenerator.init(spec)
        return keyGenerator.generateKey()
    }

    companion object {
        private const val KEYSTORE_PROVIDER = "AndroidKeyStore"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
    }
}
