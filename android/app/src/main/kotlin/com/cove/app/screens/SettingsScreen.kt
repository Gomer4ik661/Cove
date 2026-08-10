package com.cove.app.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.selection.selectable
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import com.cove.app.security.BiometricVault
import com.cove.app.storage.ThemeMode

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(
    containerPath: String,
    themeMode: ThemeMode,
    onThemeModeChange: (ThemeMode) -> Unit,
    onBack: () -> Unit,
) {
    val context = LocalContext.current
    val vault = remember { BiometricVault(context) }
    var biometricEnrolled by remember { mutableStateOf(vault.hasSavedCredentials(containerPath)) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Настройки") },
                navigationIcon = { TextButton(onClick = onBack) { Text("Назад") } },
            )
        },
    ) { padding ->
        Column(modifier = Modifier.fillMaxSize().padding(padding).padding(24.dp)) {
            Text("Тема", style = MaterialTheme.typography.titleMedium)
            Column(Modifier.padding(top = 8.dp, bottom = 16.dp)) {
                ThemeOption("Системная", ThemeMode.SYSTEM, themeMode, onThemeModeChange)
                ThemeOption("Светлая", ThemeMode.LIGHT, themeMode, onThemeModeChange)
                ThemeOption("Тёмная", ThemeMode.DARK, themeMode, onThemeModeChange)
            }

            HorizontalDivider()

            Text(
                "Безопасность",
                style = MaterialTheme.typography.titleMedium,
                modifier = Modifier.padding(top = 16.dp, bottom = 8.dp),
            )
            if (biometricEnrolled) {
                Text(
                    "Вход по биометрии включён для этого хранилища.",
                    style = MaterialTheme.typography.bodySmall,
                    modifier = Modifier.padding(bottom = 8.dp),
                )
                OutlinedButton(onClick = {
                    vault.forget(containerPath)
                    biometricEnrolled = false
                }) { Text("Забыть биометрию для этого хранилища") }
            } else {
                Text(
                    "Биометрия для этого хранилища не настроена — включить её можно на экране входа при следующем ручном входе паролем.",
                    style = MaterialTheme.typography.bodySmall,
                )
            }
        }
    }
}

@Composable
private fun ThemeOption(
    label: String,
    value: ThemeMode,
    current: ThemeMode,
    onSelect: (ThemeMode) -> Unit,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .selectable(selected = current == value, onClick = { onSelect(value) })
            .padding(vertical = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.Start,
    ) {
        RadioButton(selected = current == value, onClick = { onSelect(value) })
        Text(label, modifier = Modifier.padding(start = 8.dp))
    }
}
