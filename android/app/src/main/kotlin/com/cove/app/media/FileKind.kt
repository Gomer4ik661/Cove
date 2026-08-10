package com.cove.app.media

/** Аналог desktop/app/file_kind.py — та же классификация по расширению,
 * используется для выбора просмотрщика (ROADMAP.md Фаза 14, доработка
 * после обнаружения что превью/просмотр на Android не портировали
 * из десктопных Фаз 7/8). */

private val IMAGE_EXT = setOf("png", "jpg", "jpeg", "gif", "webp", "bmp", "heif", "heic")
private val VIDEO_EXT = setOf("mp4", "mkv", "avi", "mov", "webm")
private val AUDIO_EXT = setOf("mp3", "flac", "aac", "ogg")
private val TEXT_EXT = setOf("txt")
private val MARKDOWN_EXT = setOf("md")

enum class FileKind { IMAGE, VIDEO, AUDIO, TEXT, MARKDOWN, UNKNOWN }

fun extensionOf(name: String): String = name.substringAfterLast('.', "").lowercase()

fun kindOf(name: String): FileKind {
    val ext = extensionOf(name)
    return when {
        ext in IMAGE_EXT -> FileKind.IMAGE
        ext in VIDEO_EXT -> FileKind.VIDEO
        ext in AUDIO_EXT -> FileKind.AUDIO
        ext in MARKDOWN_EXT -> FileKind.MARKDOWN
        ext in TEXT_EXT -> FileKind.TEXT
        else -> FileKind.UNKNOWN
    }
}

fun mimeOf(name: String): String = when (kindOf(name)) {
    FileKind.IMAGE -> when (extensionOf(name)) {
        "png" -> "image/png"
        "gif" -> "image/gif"
        "webp" -> "image/webp"
        else -> "image/jpeg"
    }
    FileKind.VIDEO -> "video/*"
    FileKind.AUDIO -> "audio/*"
    FileKind.TEXT, FileKind.MARKDOWN -> "text/plain"
    FileKind.UNKNOWN -> when (extensionOf(name)) {
        "pdf" -> "application/pdf"
        else -> "application/octet-stream"
    }
}
