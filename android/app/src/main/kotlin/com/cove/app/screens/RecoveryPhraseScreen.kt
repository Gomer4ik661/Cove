package com.cove.app.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp

/**
 * Показывается РОВНО ОДИН раз, сразу после создания хранилища — фраза
 * восстановления нигде не сохраняется Core (ARCHITECTURE.md), это
 * единственный шанс пользователя её увидеть. Аналог
 * desktop/app/recovery_phrase_dialog.py.
 */
@Composable
fun RecoveryPhraseScreen(phrase: String, onConfirmed: () -> Unit) {
    Column(
        modifier = Modifier.fillMaxSize().padding(24.dp),
        verticalArrangement = Arrangement.Top,
    ) {
        Text("Фраза восстановления", style = MaterialTheme.typography.headlineSmall)
        Text(
            "Запишите эту фразу и храните её в надёжном месте отдельно от устройства. " +
                "Она — единственный способ восстановить доступ, если вы забудете пароль. " +
                "Cove не хранит её и не сможет показать снова.",
            style = MaterialTheme.typography.bodySmall,
            modifier = Modifier.padding(top = 8.dp, bottom = 16.dp),
        )

        Card(modifier = Modifier.fillMaxWidth().padding(bottom = 24.dp)) {
            Text(
                phrase,
                fontFamily = FontFamily.Monospace,
                style = MaterialTheme.typography.bodyLarge,
                modifier = Modifier.padding(16.dp),
            )
        }

        Button(onClick = onConfirmed, modifier = Modifier.fillMaxWidth()) {
            Text("Я записал фразу")
        }
    }
}
