@file:OptIn(androidx.media3.common.util.UnstableApi::class)

package com.cove.app.media

import android.net.Uri
import androidx.media3.common.C
import androidx.media3.datasource.BaseDataSource
import androidx.media3.datasource.DataSource
import androidx.media3.datasource.DataSpec
import uniffi.cove_core_uniffi.AndroidContainer
import java.io.IOException

/** media3 DataSource, стримящий байты напрямую из зашифрованного
 * контейнера через container.readAt() — Android-аналог desktop
 * ContainerFileDevice (app/container_io_device.py, ROADMAP.md Фаза 7):
 * ни один temp-файл с расшифрованным видео/аудио никогда не создаётся на
 * диске (ARCHITECTURE.md §4). `Container` остаётся собственностью
 * вызывающей стороны — `close()` этого DataSource его не закрывает. */
class ContainerDataSource(
    private val container: AndroidContainer,
    private val fileId: ULong,
    private val fileSize: Long,
) : BaseDataSource(/* isNetwork = */ false) {

    private var position: Long = 0
    private var bytesRemaining: Long = 0
    private var opened = false

    override fun open(dataSpec: DataSpec): Long {
        transferInitializing(dataSpec)
        position = dataSpec.position
        bytesRemaining = if (dataSpec.length != C.LENGTH_UNSET.toLong()) {
            dataSpec.length
        } else {
            fileSize - position
        }
        if (bytesRemaining < 0) {
            throw IOException("readAt за пределами файла: offset=$position, size=$fileSize")
        }
        opened = true
        transferStarted(dataSpec)
        return bytesRemaining
    }

    override fun read(buffer: ByteArray, offset: Int, length: Int): Int {
        if (length == 0) return 0
        if (bytesRemaining == 0L) return C.RESULT_END_OF_INPUT

        val toRead = minOf(length.toLong(), bytesRemaining).toInt()
        val chunk = container.readAt(fileId, position.toULong(), toRead.toUInt())
        if (chunk.isEmpty()) return C.RESULT_END_OF_INPUT

        chunk.copyInto(buffer, offset)
        position += chunk.size
        bytesRemaining -= chunk.size
        bytesTransferred(chunk.size)
        return chunk.size
    }

    override fun getUri(): Uri? = null

    override fun close() {
        if (opened) {
            opened = false
            transferEnded()
        }
    }
}

class ContainerDataSourceFactory(
    private val container: AndroidContainer,
    private val fileId: ULong,
    private val fileSize: Long,
) : DataSource.Factory {
    override fun createDataSource(): DataSource = ContainerDataSource(container, fileId, fileSize)
}
