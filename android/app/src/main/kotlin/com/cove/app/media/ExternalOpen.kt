package com.cove.app.media

import android.content.Context
import android.content.Intent
import android.net.Uri
import androidx.core.content.FileProvider
import uniffi.cove_core_uniffi.AndroidContainer
import uniffi.cove_core_uniffi.FileEntry
import java.io.File

/** Аналог desktop/app/external_open.py — для типов без встроенного
 * просмотрщика (pdf, RAW и т.п.) честно предлагаем открыть во внешнем
 * приложении вместо того, чтобы тап на файл ничего не делал.
 *
 * Расшифрованная копия попадает в cacheDir/exports (не в общедоступное
 * хранилище) и отдаётся другому приложению только через content://-URI
 * от FileProvider с разовым разрешением на чтение — тот же принцип
 * "минимум времени и видимости для plaintext", что и у SAF-экспорта.
 *
 * Разделено на две функции: сама расшифровка/запись — блокирующая
 * FFI+I/O работа, вызывающая сторона обязана звать её из Dispatchers.IO;
 * запуск intent'а — обязательно на главном потоке.
 */
fun exportForExternalOpen(context: Context, container: AndroidContainer, entry: FileEntry): Uri {
    val exportsDir = File(context.cacheDir, "exports").apply { mkdirs() }
    val dest = File(exportsDir, entry.name)
    val data = container.readAt(entry.fileId, 0uL, entry.size.toUInt())
    dest.writeBytes(data)
    return FileProvider.getUriForFile(context, "com.cove.app.fileprovider", dest)
}

fun launchExternalViewIntent(context: Context, uri: Uri, name: String) {
    val intent = Intent(Intent.ACTION_VIEW).apply {
        setDataAndType(uri, mimeOf(name))
        addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
    }
    context.startActivity(Intent.createChooser(intent, name))
}
