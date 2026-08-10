package com.cove.app.screens

import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import com.cove.app.media.decodeBitmap
import com.cove.app.media.exportForExternalOpen
import com.cove.app.media.launchExternalViewIntent
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import uniffi.cove_core_uniffi.AndroidContainer
import uniffi.cove_core_uniffi.FileEntry

/** Полноэкранный просмотр изображения — читает файл целиком через
 * readAt() и декодирует в память, без временных файлов на диске
 * (ROADMAP.md Фаза 14, доработка после того как обнаружилось, что тап на
 * фото вообще ничего не делал — просмотрщики из десктопных Фаз 7/8 на
 * Android не портировали). */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ImageViewerScreen(container: AndroidContainer, entry: FileEntry, onBack: () -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var bitmap by remember { mutableStateOf<android.graphics.Bitmap?>(null) }
    var failed by remember { mutableStateOf(false) }
    var loading by remember { mutableStateOf(true) }

    LaunchedEffect(entry.fileId) {
        loading = true
        failed = false
        val decoded = withContext(Dispatchers.IO) {
            val bytes = container.readAt(entry.fileId, 0uL, entry.size.toUInt())
            decodeBitmap(bytes)
        }
        bitmap = decoded
        failed = decoded == null
        loading = false
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text(entry.name) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.Filled.ArrowBack, contentDescription = "Назад")
                    }
                },
            )
        },
    ) { padding ->
        Box(
            modifier = Modifier.fillMaxSize().padding(padding).background(Color.Black),
            contentAlignment = Alignment.Center,
        ) {
            when {
                loading -> CircularProgressIndicator()
                failed -> Column(
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.spacedBy(16.dp),
                ) {
                    Text(
                        "Не удалось декодировать изображение на этом устройстве",
                        color = Color.White,
                        style = MaterialTheme.typography.bodyMedium,
                    )
                    Button(onClick = {
                        scope.launch {
                            val uri = withContext(Dispatchers.IO) {
                                exportForExternalOpen(context, container, entry)
                            }
                            launchExternalViewIntent(context, uri, entry.name)
                        }
                    }) { Text("Открыть во внешнем приложении") }
                }
                else -> Image(
                    bitmap = bitmap!!.asImageBitmap(),
                    contentDescription = entry.name,
                    contentScale = ContentScale.Fit,
                    modifier = Modifier.fillMaxSize(),
                )
            }
        }
    }
}
