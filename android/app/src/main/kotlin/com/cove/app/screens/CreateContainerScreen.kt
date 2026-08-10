package com.cove.app.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import uniffi.cove_core_uniffi.AndroidException
import uniffi.cove_core_uniffi.createContainer

@Composable
fun CreateContainerScreen(
    path: String,
    onCancel: () -> Unit,
    onCreated: (recoveryPhrase: String, container: uniffi.cove_core_uniffi.AndroidContainer) -> Unit,
) {
    var username by remember { mutableStateOf("") }
    var password by remember { mutableStateOf("") }
    var confirmPassword by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }
    var busy by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()

    Column(
        modifier = Modifier.fillMaxSize().padding(24.dp),
        verticalArrangement = Arrangement.Top,
    ) {
        Text("Новое хранилище", style = MaterialTheme.typography.headlineSmall)
        Text(
            "Придумайте имя администратора и пароль. Пароль нельзя будет восстановить без фразы восстановления, которая появится на следующем шаге.",
            style = MaterialTheme.typography.bodySmall,
            modifier = Modifier.padding(top = 8.dp, bottom = 16.dp),
        )

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
        OutlinedTextField(
            value = confirmPassword,
            onValueChange = { confirmPassword = it; error = null },
            label = { Text("Повторите пароль") },
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
                    when {
                        username.isBlank() -> error = "Введите имя пользователя"
                        password.isEmpty() -> error = "Введите пароль"
                        password != confirmPassword -> error = "Пароли не совпадают"
                        else -> {
                            busy = true
                            scope.launch {
                                try {
                                    // Argon2id — тяжёлая CPU-операция, не должна идти в UI-потоке.
                                    val result = withContext(Dispatchers.IO) {
                                        createContainer(path, username, password)
                                    }
                                    onCreated(result.recoveryPhrase, result.container)
                                } catch (e: AndroidException) {
                                    error = "Не удалось создать хранилище: ${e.message}"
                                    busy = false
                                }
                            }
                        }
                    }
                },
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text("Создать")
            }
            TextButton(onClick = onCancel, modifier = Modifier.fillMaxWidth()) {
                Text("Отмена")
            }
        }
    }
}
