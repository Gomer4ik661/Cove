package com.cove.app.screens

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.OutlinedTextField
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import com.cove.app.BuildConfig
import com.cove.app.security.BiometricVault
import com.cove.app.storage.AppSettings
import com.cove.app.storage.ThemeMode
import com.cove.app.update.UpdateChecker
import com.cove.app.webserver.WebServerService
import com.cove.app.webserver.WebServerState
import com.cove.app.webserver.WebServerStatus
import java.net.Inet4Address
import java.net.NetworkInterface
import kotlinx.coroutines.launch

// По прямой просьбе пользователя — как и на Desktop (settings_dialog.py,
// DELETE_CONFIRM_PHRASE) — удаление хранилища требует набрать это слово
// вручную, случайный тап не должен сносить все данные.
private const val DELETE_CONFIRM_PHRASE = "УДАЛИТЬ"

// Те же варианты и значения, что Desktop settings_dialog.py (AUTO_LOCK_OPTIONS).
private val AUTO_LOCK_OPTIONS = listOf(
    "Никогда" to 0,
    "5 минут" to 5,
    "15 минут" to 15,
    "30 минут" to 30,
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(
    containerPath: String,
    themeMode: ThemeMode,
    onThemeModeChange: (ThemeMode) -> Unit,
    onBack: () -> Unit,
    onDeleteDatabase: () -> Unit,
) {
    val context = LocalContext.current
    val vault = remember { BiometricVault(context) }
    var biometricEnrolled by remember { mutableStateOf(vault.hasSavedCredentials(containerPath)) }
    var showDeleteDialog by remember { mutableStateOf(false) }
    var deleteConfirmText by remember { mutableStateOf("") }

    val scope = rememberCoroutineScope()
    var updateStatus by remember { mutableStateOf<String?>(null) }
    var updateChecking by remember { mutableStateOf(false) }
    var releaseUrl by remember { mutableStateOf<String?>(null) }

    // Веб-доступ (ROADMAP.md, "веб-морда в Android") — состояние читаем из
    // WebServerStatus (единая точка правды, которую пишет сам сервис), а не
    // храним локально: иначе после сворачивания/возврата в приложение экран
    // не знал бы, что сервер на самом деле уже (или всё ещё) работает.
    val appSettings = remember { AppSettings(context) }
    var autoLockMinutes by remember { mutableStateOf(appSettings.autoLockMinutes()) }
    var loginAttemptLimitText by remember { mutableStateOf(appSettings.loginAttemptLimit().toString()) }
    var webPort by remember { mutableStateOf(appSettings.webPort()) }
    val webState by WebServerStatus.state.collectAsState()
    val notificationPermissionLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { _ ->
        // Гранттед или нет — всё равно запускаем: без разрешения сервис
        // просто не сможет показать уведомление (Android 13+), но сам
        // веб-сервер это не блокирует, деградация некритичная.
        WebServerService.start(context, containerPath, webPort)
    }

    fun startWebServer() {
        appSettings.setWebPort(webPort)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS)
                != PackageManager.PERMISSION_GRANTED
        ) {
            notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
        } else {
            WebServerService.start(context, containerPath, webPort)
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Настройки") },
                navigationIcon = { TextButton(onClick = onBack) { Text("Назад") } },
            )
        },
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .verticalScroll(rememberScrollState())
                .padding(24.dp),
        ) {
            Text("Тема", style = MaterialTheme.typography.titleMedium)
            Column(Modifier.padding(top = 8.dp, bottom = 16.dp)) {
                ThemeOption("Системная", ThemeMode.SYSTEM, themeMode, onThemeModeChange)
                ThemeOption("Светлая", ThemeMode.LIGHT, themeMode, onThemeModeChange)
                ThemeOption("Тёмная", ThemeMode.DARK, themeMode, onThemeModeChange)
            }

            HorizontalDivider()

            Text(
                "Безопасность",
                style = MaterialTheme.typography.titleMedium,
                modifier = Modifier.padding(top = 16.dp, bottom = 8.dp),
            )
            if (biometricEnrolled) {
                Text(
                    "Вход по биометрии включён для этого хранилища.",
                    style = MaterialTheme.typography.bodySmall,
                    modifier = Modifier.padding(bottom = 8.dp),
                )
                OutlinedButton(onClick = {
                    vault.forget(containerPath)
                    biometricEnrolled = false
                }) { Text("Забыть биометрию для этого хранилища") }
            } else {
                Text(
                    "Биометрия для этого хранилища не настроена — включить её можно на экране входа при следующем ручном входе паролем.",
                    style = MaterialTheme.typography.bodySmall,
                )
            }

            Text(
                "Автоблокировка через:",
                style = MaterialTheme.typography.bodyMedium,
                modifier = Modifier.padding(top = 12.dp),
            )
            Column(Modifier.padding(top = 4.dp, bottom = 8.dp)) {
                for ((label, minutes) in AUTO_LOCK_OPTIONS) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .selectable(
                                selected = autoLockMinutes == minutes,
                                onClick = {
                                    autoLockMinutes = minutes
                                    appSettings.setAutoLockMinutes(minutes)
                                },
                            )
                            .padding(vertical = 4.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        RadioButton(
                            selected = autoLockMinutes == minutes,
                            onClick = { autoLockMinutes = minutes; appSettings.setAutoLockMinutes(minutes) },
                        )
                        Text(label, modifier = Modifier.padding(start = 8.dp))
                    }
                }
            }

            OutlinedTextField(
                value = loginAttemptLimitText,
                onValueChange = { text ->
                    loginAttemptLimitText = text
                    text.toIntOrNull()?.let { appSettings.setLoginAttemptLimit(it.coerceIn(0, 20)) }
                },
                label = { Text("Лимит попыток входа (0 = без лимита)") },
                singleLine = true,
                modifier = Modifier.padding(bottom = 8.dp),
            )

            HorizontalDivider()

            Text(
                "Обновления",
                style = MaterialTheme.typography.titleMedium,
                modifier = Modifier.padding(top = 16.dp, bottom = 8.dp),
            )
            Text(
                "Текущая версия: ${BuildConfig.VERSION_NAME}",
                style = MaterialTheme.typography.bodySmall,
                modifier = Modifier.padding(bottom = 8.dp),
            )
            OutlinedButton(
                enabled = !updateChecking,
                onClick = {
                    updateChecking = true
                    updateStatus = "Проверка…"
                    releaseUrl = null
                    scope.launch {
                        try {
                            val result = UpdateChecker.checkForUpdates(BuildConfig.VERSION_NAME)
                            updateStatus = if (result.updateAvailable) {
                                releaseUrl = result.releaseUrl
                                "Доступна новая версия: ${result.latestVersion} (у вас ${BuildConfig.VERSION_NAME})"
                            } else {
                                "У вас последняя версия."
                            }
                        } catch (e: UpdateChecker.UpdateCheckException) {
                            updateStatus = "Не удалось проверить: ${e.message}"
                        } finally {
                            updateChecking = false
                        }
                    }
                },
            ) { Text("Проверить обновления") }
            updateStatus?.let {
                Text(
                    it,
                    style = MaterialTheme.typography.bodySmall,
                    modifier = Modifier.padding(top = 8.dp),
                )
            }
            releaseUrl?.let { url ->
                TextButton(onClick = {
                    context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url)))
                }) { Text("Открыть страницу релиза") }
            }

            HorizontalDivider()

            Text(
                "Веб-доступ",
                style = MaterialTheme.typography.titleMedium,
                modifier = Modifier.padding(top = 16.dp, bottom = 8.dp),
            )
            Text(
                "Открывает это хранилище по HTTPS для устройств в той же "
                    + "локальной сети, пока сервер запущен (тот же принцип, "
                    + "что и Desktop-версия). Сертификат самоподписанный — "
                    + "браузер честно предупредит при первом заходе. Не "
                    + "редактируйте одновременно через приложение и через "
                    + "веб — файл хранилища не защищён межпроцессной "
                    + "блокировкой, более поздняя запись молча перезапишет "
                    + "более раннюю.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.error,
                modifier = Modifier.padding(bottom = 8.dp),
            )
            val running = webState as? WebServerState.Running
            OutlinedTextField(
                value = webPort.toString(),
                onValueChange = { text -> text.toIntOrNull()?.let { webPort = it.coerceIn(1, 65535) } },
                label = { Text("Порт") },
                enabled = running == null,
                singleLine = true,
                modifier = Modifier.padding(bottom = 8.dp),
            )
            val statusText = when (val s = webState) {
                is WebServerState.Stopped -> "Не запущен"
                is WebServerState.Starting -> "Запускается…"
                is WebServerState.Running -> "Запущен: https://${localLanAddress()}:${s.port}"
                is WebServerState.Error -> "Ошибка: ${s.message}"
            }
            Text(statusText, style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(bottom = 8.dp))
            OutlinedButton(onClick = {
                if (running != null) {
                    WebServerService.stop(context)
                } else {
                    startWebServer()
                }
            }) { Text(if (running != null) "Остановить" else "Запустить") }

            HorizontalDivider()

            Text(
                "Хранилище",
                style = MaterialTheme.typography.titleMedium,
                modifier = Modifier.padding(top = 16.dp, bottom = 8.dp),
            )
            Text(
                "Безвозвратно удаляет файл хранилища со всеми файлами, "
                    + "пользователями и журналом входов. Резервных копий "
                    + "приложение не хранит — отменить это действие невозможно.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.error,
                modifier = Modifier.padding(bottom = 8.dp),
            )
            OutlinedButton(
                onClick = { showDeleteDialog = true },
                colors = ButtonDefaults.outlinedButtonColors(contentColor = MaterialTheme.colorScheme.error),
            ) { Text("Удалить базу данных…") }
        }
    }

    if (showDeleteDialog) {
        AlertDialog(
            onDismissRequest = {
                showDeleteDialog = false
                deleteConfirmText = ""
            },
            title = { Text("Удалить базу данных") },
            text = {
                Column {
                    Text(
                        "Хранилище и все данные в нём ($containerPath) будут "
                            + "удалены навсегда.\n\nЧтобы подтвердить, введите "
                            + "слово \"$DELETE_CONFIRM_PHRASE\":",
                    )
                    OutlinedTextField(
                        value = deleteConfirmText,
                        onValueChange = { deleteConfirmText = it },
                        singleLine = true,
                        modifier = Modifier.padding(top = 12.dp),
                    )
                }
            },
            confirmButton = {
                TextButton(
                    enabled = deleteConfirmText.trim() == DELETE_CONFIRM_PHRASE,
                    onClick = {
                        showDeleteDialog = false
                        deleteConfirmText = ""
                        vault.forget(containerPath)
                        onDeleteDatabase()
                    },
                ) { Text("Удалить навсегда", color = MaterialTheme.colorScheme.error) }
            },
            dismissButton = {
                TextButton(onClick = {
                    showDeleteDialog = false
                    deleteConfirmText = ""
                }) { Text("Отмена") }
            },
        )
    }
}

@Composable
private fun ThemeOption(
    label: String,
    value: ThemeMode,
    current: ThemeMode,
    onSelect: (ThemeMode) -> Unit,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .selectable(selected = current == value, onClick = { onSelect(value) })
            .padding(vertical = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.Start,
    ) {
        RadioButton(selected = current == value, onClick = { onSelect(value) })
        Text(label, modifier = Modifier.padding(start = 8.dp))
    }
}

/** Первый неloopback IPv4-адрес устройства — best-effort, тот же смысл,
 * что `_local_lan_address()` в desktop/app/settings_dialog.py (там через
 * `socket.gethostbyname`, здесь через перебор сетевых интерфейсов — на
 * Android это надёжнее, т.к. `gethostbyname(hostname)`-эквивалента для
 * "IP этого устройства в Wi-Fi сети" не гарантировано существует). */
private fun localLanAddress(): String {
    try {
        val interfaces = NetworkInterface.getNetworkInterfaces() ?: return "<ip-этого-устройства>"
        for (iface in interfaces.toList()) {
            if (iface.isLoopback || !iface.isUp) continue
            for (addr in iface.inetAddresses.toList()) {
                if (addr is Inet4Address) return addr.hostAddress ?: continue
            }
        }
    } catch (_: Exception) {
        // best-effort — если перечисление интерфейсов недоступно, честно
        // показываем заглушку вместо падения экрана настроек.
    }
    return "<ip-этого-устройства>"
}
