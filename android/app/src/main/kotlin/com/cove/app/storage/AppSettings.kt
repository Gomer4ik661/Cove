package com.cove.app.storage

import android.content.Context

enum class ThemeMode { SYSTEM, LIGHT, DARK }

/** Настройки приложения, не привязанные к конкретному хранилищу (в отличие
 * от ContainerRegistry) — пока только тема, живёт в обычных, не
 * зашифрованных SharedPreferences, т.к. сама по себе ничего чувствительного
 * не хранит. */
class AppSettings(context: Context) {
    private val prefs = context.applicationContext.getSharedPreferences("cove_app_settings", Context.MODE_PRIVATE)

    fun themeMode(): ThemeMode =
        when (prefs.getString(KEY_THEME, null)) {
            "light" -> ThemeMode.LIGHT
            "dark" -> ThemeMode.DARK
            else -> ThemeMode.SYSTEM
        }

    fun setThemeMode(mode: ThemeMode) {
        val value = when (mode) {
            ThemeMode.LIGHT -> "light"
            ThemeMode.DARK -> "dark"
            ThemeMode.SYSTEM -> "system"
        }
        prefs.edit().putString(KEY_THEME, value).apply()
    }

    companion object {
        private const val KEY_THEME = "theme_mode"
    }
}
