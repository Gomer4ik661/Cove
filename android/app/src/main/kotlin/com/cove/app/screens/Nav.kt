package com.cove.app.screens

import uniffi.cove_core_uniffi.AndroidContainer

/**
 * Простая sealed-навигация без Navigation-Compose — для объёма экранов в
 * этой фазе (приветствие/вход/библиотека) полноценный роутер был бы
 * преждевременной абстракцией; если экранов станет заметно больше, есть
 * смысл вернуться к этому решению.
 */
sealed class Screen {
    data object Welcome : Screen()
    data class Login(val path: String) : Screen()
    data object CreateContainer : Screen()
    data class RecoveryPhrase(val phrase: String, val container: AndroidContainer, val path: String) : Screen()
    data class Library(val container: AndroidContainer, val path: String) : Screen()
}
