package com.cove.app.update

import java.security.SecureRandom
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.bouncycastle.util.encoders.Base64
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/** Реальные тесты UpdateChecker — без сети, без эмулятора (`src/test`,
 * чистая JVM), но с настоящей Ed25519-подписью через отдельный тестовый
 * keypair (НЕ release-signing-key.pem проекта — тот в .gitignore и не
 * должен попадать даже в тестовый код, см. verifyManifestSignature). */
class UpdateCheckerTest {

    private val keyPair = run {
        val generator = Ed25519KeyPairGenerator()
        generator.init(Ed25519KeyGenerationParameters(SecureRandom()))
        generator.generateKeyPair()
    }
    private val testPrivateKey = keyPair.private as Ed25519PrivateKeyParameters
    private val testPublicKeyB64 =
        Base64.toBase64String((keyPair.public as Ed25519PublicKeyParameters).encoded)

    private fun sign(data: ByteArray): String {
        val signer = Ed25519Signer()
        signer.init(true, testPrivateKey)
        signer.update(data, 0, data.size)
        return Base64.toBase64String(signer.generateSignature())
    }

    @Test
    fun `verifyManifestSignature accepts valid signature`() {
        val manifest = """{"version":"1.2.3"}""".toByteArray(Charsets.UTF_8)
        UpdateChecker.verifyManifestSignature(manifest, sign(manifest), testPublicKeyB64) // не должно кинуть
    }

    @Test
    fun `verifyManifestSignature rejects tampered manifest`() {
        val manifest = """{"version":"1.2.3"}""".toByteArray(Charsets.UTF_8)
        val sig = sign(manifest)
        val tampered = """{"version":"9.9.9"}""".toByteArray(Charsets.UTF_8)
        try {
            UpdateChecker.verifyManifestSignature(tampered, sig, testPublicKeyB64)
            fail("должно было кинуть UpdateCheckException на подделанный манифест")
        } catch (e: UpdateChecker.UpdateCheckException) {
            // ожидаемо
        }
    }

    @Test
    fun `verifyManifestSignature rejects signature from wrong key`() {
        // Валидная подпись, но НЕ тем ключом, которому мы доверяем —
        // должно проваливаться так же, как и "подпись вообще не сошлась".
        val otherGenerator = Ed25519KeyPairGenerator()
        otherGenerator.init(Ed25519KeyGenerationParameters(SecureRandom()))
        val otherKeyPair = otherGenerator.generateKeyPair()
        val otherSigner = Ed25519Signer()
        otherSigner.init(true, otherKeyPair.private as Ed25519PrivateKeyParameters)
        val manifest = """{"version":"1.2.3"}""".toByteArray(Charsets.UTF_8)
        otherSigner.update(manifest, 0, manifest.size)
        val wrongSig = Base64.toBase64String(otherSigner.generateSignature())

        try {
            UpdateChecker.verifyManifestSignature(manifest, wrongSig, testPublicKeyB64)
            fail("должно было кинуть UpdateCheckException на чужую подпись")
        } catch (e: UpdateChecker.UpdateCheckException) {
            // ожидаемо
        }
    }

    @Test
    fun `verifyManifestSignature rejects garbage base64`() {
        try {
            UpdateChecker.verifyManifestSignature(
                "irrelevant".toByteArray(),
                "not valid base64!!!",
                testPublicKeyB64,
            )
            fail("должно было кинуть UpdateCheckException на невалидный base64")
        } catch (e: UpdateChecker.UpdateCheckException) {
            // ожидаемо
        }
    }

    @Test
    fun `parseVersion and compareVersions order correctly`() {
        assertTrue(
            UpdateChecker.compareVersions(
                UpdateChecker.parseVersion("0.1.0"),
                UpdateChecker.parseVersion("0.2.0"),
            ) < 0
        )
        assertTrue(
            UpdateChecker.compareVersions(
                UpdateChecker.parseVersion("1.0.0"),
                UpdateChecker.parseVersion("0.99.99"),
            ) > 0
        )
        assertEquals(
            0,
            UpdateChecker.compareVersions(
                UpdateChecker.parseVersion("1.2.3"),
                UpdateChecker.parseVersion("1.2.3"),
            ),
        )
    }

    @Test
    fun `parseVersion rejects non-numeric version`() {
        try {
            UpdateChecker.parseVersion("not-a-version")
            fail("должно было кинуть UpdateCheckException")
        } catch (e: UpdateChecker.UpdateCheckException) {
            // ожидаемо
        }
    }
}
