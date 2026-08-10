package com.cove.app.media

import android.graphics.Bitmap
import android.graphics.BitmapFactory
import java.io.ByteArrayOutputStream

/** Аналог desktop/app/thumbnails.py — тот же размер (160px по большей
 * стороне) и формат (PNG), чтобы миниатюры, сделанные на одной платформе,
 * не выглядели неуместно "другими" на другой (обе хранятся одинаково —
 * internal-запись File Table, ROADMAP.md Фаза 8). */
const val THUMBNAIL_SIZE = 160

/** Декодирует изображение и уменьшает до миниатюры, отдаёт PNG-байты.
 * `null`, если Android не смог декодировать исходные байты — вызывающая
 * сторона не должна писать что-либо, кроме готового PNG, в Container
 * (ни исходные, ни промежуточные байты никогда не попадают на диск как
 * есть — только через тот же зашифрованный путь, что и обычный файл). */
fun generateThumbnailBytes(sourceBytes: ByteArray, maxSize: Int = THUMBNAIL_SIZE): ByteArray? {
    val original = BitmapFactory.decodeByteArray(sourceBytes, 0, sourceBytes.size) ?: return null
    val scale = maxSize.toFloat() / maxOf(original.width, original.height)
    val scaled = if (scale < 1f) {
        Bitmap.createScaledBitmap(
            original,
            (original.width * scale).toInt().coerceAtLeast(1),
            (original.height * scale).toInt().coerceAtLeast(1),
            true,
        )
    } else {
        original
    }
    val out = ByteArrayOutputStream()
    val ok = scaled.compress(Bitmap.CompressFormat.PNG, 100, out)
    if (scaled !== original) scaled.recycle()
    original.recycle()
    return if (ok) out.toByteArray() else null
}

fun decodeBitmap(bytes: ByteArray): Bitmap? = BitmapFactory.decodeByteArray(bytes, 0, bytes.size)
