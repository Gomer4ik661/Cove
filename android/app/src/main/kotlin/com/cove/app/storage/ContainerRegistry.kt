package com.cove.app.storage

import android.content.Context
import java.io.File

/**
 * Список локально известных хранилищ — аналог `recent_containers` в
 * desktop/app/config.py, но на Android хранилища физически живут в
 * app-private storage (`filesDir/containers/`), а не там, куда указал
 * пользователь: прямого доступа к произвольным путям файловой системы нет
 * (Scoped Storage), только через SAF-импорт (Фаза 14, задача SAF — отдельная).
 *
 * Пути НЕ секретны сами по себе, но, как и в desktop THREAT_MODEL.md,
 * список путей может выдавать сам факт существования хранилища — поэтому
 * хранится в обычных SharedPreferences приложения (private mode), не в
 * общем месте.
 */
class ContainerRegistry(context: Context) {
    private val appContext = context.applicationContext
    private val prefs = appContext.getSharedPreferences("cove_containers", Context.MODE_PRIVATE)

    fun containersDir(): File {
        val dir = File(appContext.filesDir, "containers")
        dir.mkdirs()
        return dir
    }

    fun listKnownPaths(): List<String> {
        val dir = containersDir()
        return dir.listFiles { f -> f.isFile && f.name.endsWith(".slr") }
            ?.map { it.absolutePath }
            ?.sorted()
            ?: emptyList()
    }

    fun pathFor(displayName: String): String {
        val safe = displayName.trim().ifEmpty { "cove" }
            .filter { it.isLetterOrDigit() || it == '-' || it == '_' || it == ' ' }
            .replace(' ', '_')
        var candidate = File(containersDir(), "$safe.slr")
        var suffix = 1
        while (candidate.exists()) {
            candidate = File(containersDir(), "${safe}_$suffix.slr")
            suffix++
        }
        return candidate.absolutePath
    }

    fun defaultContainerPath(): String? = prefs.getString(KEY_DEFAULT, null)

    fun setDefaultContainerPath(path: String) {
        prefs.edit().putString(KEY_DEFAULT, path).apply()
    }

    fun clearDefaultContainerPath() {
        prefs.edit().remove(KEY_DEFAULT).apply()
    }

    companion object {
        private const val KEY_DEFAULT = "default_container_path"
    }
}
