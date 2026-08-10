package com.cove.app

import android.os.Bundle
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
        val registry = ContainerRegistry(this)
        val appSettings = AppSettings(this)
        setContent {
            CoveApp(registry, appSettings)
        }
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
                    themeMode = themeMode,
                    onThemeModeChange = {
                        themeMode = it
                        appSettings.setThemeMode(it)
                    },
                    // LibraryScreen сам дожидается closeContainer() (реальный
                    // commit на диск) перед тем как вызвать этот колбэк — см.
                    // комментарий там же про то, почему это важно.
                    onLogout = { screen = Screen.Welcome },
                )
            }
        }
    }
}
