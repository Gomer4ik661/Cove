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

    /** Только предпочтение порта — как и на Desktop (settings.json
     * `web_port`), НЕ флаг "запускать сервер автоматически": сервер
     * стартует лишь по явному нажатию в настройках, каждый раз заново. */
    fun webPort(): Int = prefs.getInt(KEY_WEB_PORT, com.cove.app.webserver.WebServerService.DEFAULT_PORT)

    fun setWebPort(port: Int) {
        prefs.edit().putInt(KEY_WEB_PORT, port).apply()
    }

    /** Та же пара настроек, что Desktop settings_dialog.py/config.py — 0
     * значит "никогда"/"без лимита" в обоих случаях. Раньше на Android не
     * было ни того, ни другого вообще: разблокированное хранилище никогда
     * не блокировалось само, а форма входа не ограничивала число попыток
     * (см. docs/FUTURE_IMPROVEMENTS.md). */
    fun autoLockMinutes(): Int = prefs.getInt(KEY_AUTO_LOCK_MINUTES, 15)

    fun setAutoLockMinutes(minutes: Int) {
        prefs.edit().putInt(KEY_AUTO_LOCK_MINUTES, minutes).apply()
    }

    fun loginAttemptLimit(): Int = prefs.getInt(KEY_LOGIN_ATTEMPT_LIMIT, 5)

    fun setLoginAttemptLimit(limit: Int) {
        prefs.edit().putInt(KEY_LOGIN_ATTEMPT_LIMIT, limit).apply()
    }

    companion object {
        private const val KEY_THEME = "theme_mode"
        private const val KEY_WEB_PORT = "web_port"
        private const val KEY_AUTO_LOCK_MINUTES = "auto_lock_minutes"
        private const val KEY_LOGIN_ATTEMPT_LIMIT = "login_attempt_limit"
    }
}
