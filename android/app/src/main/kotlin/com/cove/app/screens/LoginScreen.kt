package com.cove.app.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
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

    var locked by remember { mutableStateOf<AndroidLockedContainer?>(null) }
    var openError by remember { mutableStateOf<String?>(null) }
    var username by remember { mutableStateOf("") }
    var password by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }
    var offerEnrollBiometric by remember { mutableStateOf<Pair<String, String>?>(null) }
    var pendingContainer by remember { mutableStateOf<AndroidContainer?>(null) }
    val scope = rememberCoroutineScope()

    val canOfferBiometricLogin = vault.isBiometricAvailable() && vault.hasSavedCredentials(path)

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
                // Намеренно один и тот же текст для неверного пароля и
                // неизвестного пользователя — ARCHITECTURE.md §3 /
                // THREAT_MODEL.md §2.1, не даём enumerate пользователей.
                error = "Неверное имя пользователя или пароль"
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

        OutlinedTextField(
            value = username,
            onValueChange = { username = it; error = null },
            label = { Text("Имя пользователя") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth().padding(bottom = 8.dp),
        )
        OutlinedTextField(
            value = password,
            onValueChange = { password = it; error = null },
            label = { Text("Пароль") },
            singleLine = true,
            visualTransformation = PasswordVisualTransformation(),
            modifier = Modifier.fillMaxWidth().padding(bottom = 8.dp),
        )

        error?.let {
            Text(it, color = MaterialTheme.colorScheme.error, modifier = Modifier.padding(bottom = 8.dp))
        }

        if (busy) {
            CircularProgressIndicator(modifier = Modifier.padding(vertical = 16.dp))
        } else {
            Button(
                onClick = {
                    val lockedContainer = locked ?: return@Button
                    finishUnlock(lockedContainer, username, password)
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
