package com.cove.app

import android.os.Bundle
import android.view.MotionEvent
import android.view.WindowManager
import androidx.activity.compose.setContent
import androidx.fragment.app.FragmentActivity
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import com.cove.app.screens.CreateContainerScreen
import com.cove.app.screens.LibraryScreen
import com.cove.app.screens.LoginScreen
import com.cove.app.screens.RecoveryPhraseScreen
import com.cove.app.screens.Screen
import com.cove.app.screens.WelcomeScreen
import com.cove.app.storage.AppSettings
import com.cove.app.storage.ContainerRegistry
import com.cove.app.storage.ThemeMode

// FragmentActivity, а не ComponentActivity — BiometricPrompt (androidx.biometric)
// требует именно его для показа системного диалога биометрии.
class MainActivity : FragmentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // FLAG_SECURE на всё окно: расшифрованный контент (превью файлов,
        // пароль на экране входа) не должен попадать в скриншоты, список
        // "последних приложений" и запись экрана — приложение одноэкранное
        // (единственная Activity), поэтому флаг на окно покрывает все экраны.
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        val registry = ContainerRegistry(this)
        val appSettings = AppSettings(this)
        setContent {
            CoveApp(registry, appSettings)
        }
    }

    // Автоблокировка (LibraryScreen) считает простой от последнего касания
    // где угодно на экране, а не только внутри конкретного Composable —
    // диалоги/дровер/выпадающие меню тоже должны сбрасывать таймер.
    // dispatchTouchEvent на Activity видит абсолютно любой тач раньше
    // Compose-дерева, не нужно протаскивать Modifier.pointerInput через
    // каждый слой UI вручную.
    override fun dispatchTouchEvent(ev: MotionEvent): Boolean {
        UserActivity.recordInteraction()
        return super.dispatchTouchEvent(ev)
    }
}

@Composable
fun CoveApp(registry: ContainerRegistry, appSettings: AppSettings) {
    // Тот же UX, что и в desktop (ROADMAP.md, "Логин напрямую"): если есть
    // основное хранилище — сразу экран входа, без выбора файла.
    var screen by remember {
        mutableStateOf<Screen>(
            registry.defaultContainerPath()?.let { Screen.Login(it) } ?: Screen.Welcome,
        )
    }
    var themeMode by remember { mutableStateOf(appSettings.themeMode()) }
    val useDark = when (themeMode) {
        ThemeMode.LIGHT -> false
        ThemeMode.DARK -> true
        ThemeMode.SYSTEM -> isSystemInDarkTheme()
    }

    MaterialTheme(colorScheme = if (useDark) darkColorScheme() else lightColorScheme()) {
        Surface(modifier = Modifier.fillMaxSize()) {
            when (val current = screen) {
                is Screen.Welcome -> WelcomeScreen(
                    knownPaths = registry.listKnownPaths(),
                    onCreateClick = { screen = Screen.CreateContainer },
                    onOpenClick = { path -> screen = Screen.Login(path) },
                )

                is Screen.CreateContainer -> {
                    val path = remember { registry.pathFor("Cove") }
                    CreateContainerScreen(
                        path = path,
                        onCancel = { screen = Screen.Welcome },
                        onCreated = { phrase, container ->
                            screen = Screen.RecoveryPhrase(phrase, container, path)
                        },
                    )
                }

                is Screen.RecoveryPhrase -> RecoveryPhraseScreen(
                    phrase = current.phrase,
                    onConfirmed = {
                        registry.setDefaultContainerPath(current.path)
                        screen = Screen.Library(current.container, current.path)
                    },
                )

                is Screen.Login -> LoginScreen(
                    path = current.path,
                    onBack = {
                        registry.clearDefaultContainerPath()
                        screen = Screen.Welcome
                    },
                    onUnlocked = { container ->
                        registry.setDefaultContainerPath(current.path)
                        screen = Screen.Library(container, current.path)
                    },
                )

                is Screen.Library -> LibraryScreen(
                    container = current.container,
                    containerPath = current.path,
                    appSettings = appSettings,
                    themeMode = themeMode,
                    onThemeModeChange = {
                        themeMode = it
                        appSettings.setThemeMode(it)
                    },
                    // LibraryScreen сам дожидается closeContainer() (реальный
                    // commit на диск) перед тем как вызвать этот колбэк — см.
                    // комментарий там же про то, почему это важно.
                    onLogout = { screen = Screen.Welcome },
                    // Удаление БД из настроек — в отличие от обычного выхода,
                    // нужно ещё забыть путь как "основное" хранилище: иначе
                    // при следующем холодном запуске CoveApp попытался бы
                    // сразу открыть Screen.Login(path) для уже не
                    // существующего файла.
                    onDatabaseDeleted = {
                        registry.clearDefaultContainerPath()
                        screen = Screen.Welcome
                    },
                )
            }
        }
    }
}
