@file:OptIn(androidx.media3.common.util.UnstableApi::class)

package com.cove.app.screens

import android.net.Uri
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.viewinterop.AndroidView
import androidx.media3.common.MediaItem
import androidx.media3.datasource.DataSource
import androidx.media3.exoplayer.ExoPlayer
import androidx.media3.exoplayer.source.ProgressiveMediaSource
import androidx.media3.ui.PlayerView
import com.cove.app.media.ContainerDataSourceFactory
import uniffi.cove_core_uniffi.AndroidContainer
import uniffi.cove_core_uniffi.FileEntry

/** Видео/аудио-плеер — media3 ExoPlayer поверх ContainerDataSource
 * (стриминг через container.readAt(), без временных файлов). Для аудио
 * PlayerView просто не показывает видеоповерхность, стандартные плеерные
 * контролы (play/pause/seek) те же самые (ROADMAP.md Фаза 14, доработка). */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MediaViewerScreen(container: AndroidContainer, entry: FileEntry, onBack: () -> Unit) {
    val context = LocalContext.current

    val player = remember(entry.fileId) {
        val dataSourceFactory: DataSource.Factory =
            ContainerDataSourceFactory(container, entry.fileId, entry.size.toLong())
        val mediaItem = MediaItem.fromUri(Uri.parse("cove://${entry.fileId}"))
        val mediaSource = ProgressiveMediaSource.Factory(dataSourceFactory).createMediaSource(mediaItem)
        ExoPlayer.Builder(context).build().apply {
            setMediaSource(mediaSource)
            prepare()
            playWhenReady = true
        }
    }

    DisposableEffect(player) {
        onDispose { player.release() }
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
        Box(modifier = Modifier.fillMaxSize().padding(padding)) {
            AndroidView(
                factory = { ctx -> PlayerView(ctx).apply { this.player = player } },
                modifier = Modifier.fillMaxSize(),
            )
        }
    }
}
