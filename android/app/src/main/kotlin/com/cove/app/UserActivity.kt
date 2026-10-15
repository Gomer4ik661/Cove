package com.cove.app

/** Отметка последнего касания экрана — обновляется из
 * MainActivity.dispatchTouchEvent() (видит любой тач до того, как он
 * дойдёт до Compose-дерева, включая диалоги/дровер/выпадающие меню — тот
 * же принцип, что Desktop QApplication.installEventFilter() в
 * main_window.py, только на уровне Activity, а не конкретного виджета).
 * Читается таймером автоблокировки в LibraryScreen. Обычный volatile var,
 * не Compose State — не должен триггерить рекомпозицию на каждый тап,
 * только читается раз в тик фонового таймера. */
object UserActivity {
    @Volatile
    var lastInteractionAtMillis: Long = System.currentTimeMillis()
        private set

    fun recordInteraction() {
        lastInteractionAtMillis = System.currentTimeMillis()
    }
}
