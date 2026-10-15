package com.cove.app.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.Row
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.ui.Alignment
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.fragment.app.FragmentActivity
import com.cove.app.security.BiometricVault
import com.cove.app.storage.AppSettings
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import uniffi.cove_core_uniffi.AndroidContainer
import uniffi.cove_core_uniffi.AndroidException
import uniffi.cove_core_uniffi.AndroidLockedContainer

/**
 * Логин/пароль напрямую — то же UX-решение, что в desktop/app/login_dialog.py.
 * Плюс биометрия как альтернатива паролю (ROADMAP.md Фаза 14,
 * security/BiometricVault.kt) — по возможности, не обязательна.
 */
@Composable
fun LoginScreen(
    path: String,
    onBack: () -> Unit,
    onUnlocked: (AndroidContainer) -> Unit,
) {
    val context = LocalContext.current
    val vault = remember { BiometricVault(context) }
    val appSettings = remember { AppSettings(context) }

    var locked by remember { mutableStateOf<AndroidLockedContainer?>(null) }
    var openError by remember { mutableStateOf<String?>(null) }
    var username by remember { mutableStateOf("") }
    var password by remember { mutableStateOf("") }
    var useRecovery by remember { mutableStateOf(false) }
    var recoveryPhrase by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }
    var offerEnrollBiometric by remember { mutableStateOf<Pair<String, String>?>(null) }
    var pendingContainer by remember { mutableStateOf<AndroidContainer?>(null) }
    // Лимит попыток входа — то же самое, что Desktop welcome_window.py
    // (_register_failed_attempt): считается только в памяти этого экрана,
    // не в Core — DEK ещё не получен на этот момент, шифровать счётчик
    // в контейнере нечем (THREAT_MODEL.md). Раньше на Android такого
    // лимита не было вообще — форма позволяла подбирать пароль без
    // единого ограничения.
    var failedAttempts by remember { mutableStateOf(0) }
    var lockedOut by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()

    // Возвращает текст, который нужно показать после неверного пароля/фразы:
    // либо "осталось N попыток", либо (при достижении лимита) сообщение о
    // блокировке формы — ровно тот же выбор текста, что в Desktop
    // welcome_window.py::_register_failed_attempt().
    fun registerFailedAttempt(wrongCredentialLabel: String): String {
        val limit = appSettings.loginAttemptLimit()
        failedAttempts++
        if (limit > 0 && failedAttempts >= limit) {
            lockedOut = true
            return "Превышен лимит попыток ($limit). Перезапустите приложение."
        }
        val remaining = if (limit > 0) " Осталось попыток: ${limit - failedAttempts}." else ""
        return "$wrongCredentialLabel$remaining"
    }

    val canOfferBiometricLogin = !lockedOut && vault.isBiometricAvailable() && vault.hasSavedCredentials(path)

    LaunchedEffect(path) {
        try {
            val opened = withContext(Dispatchers.IO) { AndroidLockedContainer.open(path) }
            locked = opened
            val names = opened.listUsernames()
            if (names.size == 1) username = names[0]
        } catch (e: AndroidException) {
            openError = "Не удалось открыть файл: ${e.message}"
        }
    }

    fun finishUnlock(lockedContainer: AndroidLockedContainer, user: String, pass: String) {
        busy = true
        scope.launch {
            try {
                val container = withContext(Dispatchers.IO) { lockedContainer.unlock(user, pass) }
                if (vault.isBiometricAvailable() && !vault.hasSavedCredentials(path)) {
                    // Не вызываем onUnlocked() сразу — экран сменится на
                    // библиотеку и этот диалог никогда не отрисуется (был
                    // найден вживую: LoginScreen уходит из композиции раньше,
                    // чем AlertDialog успевает показаться). Ждём ответа.
                    pendingContainer = container
                    offerEnrollBiometric = user to pass
                } else {
                    onUnlocked(container)
                }
            } catch (e: AndroidException) {
                // Раньше здесь был один и тот же текст для ЛЮБОЙ ошибки
                // разблокировки — оправдано только для AuthFailed
                // (ARCHITECTURE.md §3 / THREAT_MODEL.md §2.1, не даём
                // enumerate пользователей неверным паролем/логином), но по
                // ошибке применялось и к FormatException — из-за чего
                // пользователь с несовместимым/повреждённым хранилищем видел
                // "неверный пароль" и не мог отличить забытый пароль от
                // реального бага (живой репорт пользователя, см. ROADMAP.md).
                error = when (e) {
                    is AndroidException.AuthFailed -> registerFailedAttempt("Неверное имя пользователя или пароль.")
                    is AndroidException.FormatException ->
                        "Не удалось прочитать хранилище — файл повреждён или несовместим с этой версией приложения. Пароль тут ни при чём."
                    else -> "Не удалось войти: ${e.message}"
                }
                busy = false
            }
        }
    }

    fun finishUnlockWithRecovery(lockedContainer: AndroidLockedContainer, phrase: String) {
        busy = true
        scope.launch {
            try {
                val container = withContext(Dispatchers.IO) { lockedContainer.unlockWithRecovery(phrase) }
                onUnlocked(container)
            } catch (e: AndroidException) {
                error = when (e) {
                    is AndroidException.AuthFailed -> registerFailedAttempt("Неверная фраза восстановления.")
                    is AndroidException.FormatException ->
                        "Не удалось прочитать хранилище — файл повреждён или несовместим с этой версией приложения. Фраза восстановления тут ни при чём."
                    else -> "Не удалось войти: ${e.message}"
                }
                busy = false
            }
        }
    }

    offerEnrollBiometric?.let { (user, pass) ->
        AlertDialog(
            onDismissRequest = {
                offerEnrollBiometric = null
                pendingContainer?.let(onUnlocked)
            },
            title = { Text("Вход по биометрии") },
            text = { Text("Включить разблокировку отпечатком пальца или лицом для этого хранилища?") },
            confirmButton = {
                TextButton(onClick = {
                    val activity = context as? FragmentActivity
                    offerEnrollBiometric = null
                    if (activity == null) {
                        pendingContainer?.let(onUnlocked)
                    } else {
                        vault.enroll(
                            activity = activity,
                            path = path,
                            username = user,
                            password = pass,
                            onSuccess = { pendingContainer?.let(onUnlocked) },
                            onError = { pendingContainer?.let(onUnlocked) },
                        )
                    }
                }) { Text("Включить") }
            },
            dismissButton = {
                TextButton(onClick = {
                    offerEnrollBiometric = null
                    pendingContainer?.let(onUnlocked)
                }) { Text("Не сейчас") }
            },
        )
    }

    Column(
        modifier = Modifier.fillMaxSize().padding(24.dp),
        verticalArrangement = Arrangement.Top,
    ) {
        Text("Вход", style = MaterialTheme.typography.headlineSmall)
        Text(path, style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(bottom = 16.dp))

        openError?.let {
            Text(it, color = MaterialTheme.colorScheme.error, modifier = Modifier.padding(bottom = 8.dp))
            TextButton(onClick = onBack) { Text("Назад") }
            return@Column
        }

        if (locked == null) {
            CircularProgressIndicator(modifier = Modifier.padding(vertical = 16.dp))
            return@Column
        }

        if (canOfferBiometricLogin && !busy) {
            OutlinedButton(
                onClick = {
                    val activity = context as? FragmentActivity ?: return@OutlinedButton
                    val lockedContainer = locked ?: return@OutlinedButton
                    vault.authenticate(
                        activity = activity,
                        path = path,
                        onSuccess = { u, p -> finishUnlock(lockedContainer, u, p) },
                        onError = { msg -> error = msg },
                        onCancel = {},
                    )
                },
                modifier = Modifier.fillMaxWidth().padding(bottom = 16.dp),
            ) {
                Text("Войти по биометрии")
            }
        }

        if (!useRecovery) {
            OutlinedTextField(
                value = username,
                onValueChange = { username = it; error = null },
                label = { Text("Имя пользователя") },
                singleLine = true,
                enabled = !lockedOut,
                modifier = Modifier.fillMaxWidth().padding(bottom = 8.dp),
            )
            OutlinedTextField(
                value = password,
                onValueChange = { password = it; error = null },
                label = { Text("Пароль") },
                singleLine = true,
                enabled = !lockedOut,
                visualTransformation = PasswordVisualTransformation(),
                modifier = Modifier.fillMaxWidth().padding(bottom = 8.dp),
            )
        } else {
            OutlinedTextField(
                value = recoveryPhrase,
                onValueChange = { recoveryPhrase = it; error = null },
                label = { Text("Фраза восстановления (12 слов)") },
                enabled = !lockedOut,
                modifier = Modifier.fillMaxWidth().padding(bottom = 8.dp),
            )
        }

        Row(
            verticalAlignment = Alignment.CenterVertically,
            modifier = Modifier.padding(bottom = 8.dp),
        ) {
            Checkbox(
                checked = useRecovery,
                onCheckedChange = { useRecovery = it; error = null },
                enabled = !busy && !lockedOut,
            )
            Text("Войти по фразе восстановления вместо пароля")
        }

        error?.let {
            Text(it, color = MaterialTheme.colorScheme.error, modifier = Modifier.padding(bottom = 8.dp))
        }

        if (busy) {
            CircularProgressIndicator(modifier = Modifier.padding(vertical = 16.dp))
        } else {
            Button(
                enabled = !lockedOut,
                onClick = {
                    val lockedContainer = locked ?: return@Button
                    if (useRecovery) {
                        finishUnlockWithRecovery(lockedContainer, recoveryPhrase)
                    } else {
                        finishUnlock(lockedContainer, username, password)
                    }
                },
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text("Войти")
            }
            TextButton(onClick = onBack, modifier = Modifier.fillMaxWidth()) {
                Text("Назад")
            }
        }
    }
}
