package com.cove.app.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import java.io.File

/**
 * Экран приветствия — только когда нет "основного" хранилища (см.
 * MainActivity: при наличии default-пути сразу открывается LoginScreen,
 * то же UX-решение, что и в desktop/app/welcome_window.py: вход должен
 * сразу спрашивать логин/пароль, а не заставлять выбирать файл каждый раз).
 */
@Composable
fun WelcomeScreen(
    knownPaths: List<String>,
    onCreateClick: () -> Unit,
    onOpenClick: (String) -> Unit,
) {
    Column(
        modifier = Modifier.fillMaxSize().padding(24.dp),
        verticalArrangement = Arrangement.Top,
    ) {
        Text("Cove", style = MaterialTheme.typography.headlineMedium)
        Text(
            "Зашифрованное файловое хранилище",
            style = MaterialTheme.typography.bodyMedium,
            modifier = Modifier.padding(bottom = 24.dp),
        )

        Button(onClick = onCreateClick, modifier = Modifier.fillMaxWidth()) {
            Text("Создать новое хранилище")
        }

        if (knownPaths.isNotEmpty()) {
            HorizontalDivider(modifier = Modifier.padding(vertical = 16.dp))
            Text("Существующие хранилища", style = MaterialTheme.typography.titleSmall)
            LazyColumn(modifier = Modifier.padding(top = 8.dp)) {
                items(knownPaths) { path ->
                    OutlinedButton(
                        onClick = { onOpenClick(path) },
                        modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
                    ) {
                        Text(File(path).nameWithoutExtension)
                    }
                }
            }
        }
    }
}
