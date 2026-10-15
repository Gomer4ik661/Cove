package com.cove.app.webserver

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.IBinder
import android.util.Log
import androidx.core.app.NotificationCompat
import com.cove.app.MainActivity
import java.io.File
import java.io.IOException
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

sealed class WebServerState {
    data object Stopped : WebServerState()
    data object Starting : WebServerState()
    data class Running(val port: Int) : WebServerState()
    data class Error(val message: String) : WebServerState()
}

/**
 * Единая точка правды о состоянии сервера — и [WebServerService], и
 * SettingsScreen читают/пишут сюда напрямую, без bindService()/AIDL. Тот же
 * принцип простоты, что и у остальной навигации приложения (sealed-экраны
 * без Navigation-Compose) — bindService() оправдан для более сложного IPC,
 * которого тут нет: сервис и Activity живут в одном процессе.
 */
object WebServerStatus {
    private val _state = MutableStateFlow<WebServerState>(WebServerState.Stopped)
    val state: StateFlow<WebServerState> = _state.asStateFlow()

    fun update(newState: WebServerState) {
        _state.value = newState
    }
}

private const val CHANNEL_ID = "web_server"
private const val NOTIFICATION_ID = 1001
private const val EXTRA_CONTAINER_PATH = "container_path"
private const val EXTRA_PORT = "port"
private const val ACTION_STOP = "com.cove.app.webserver.STOP"

/**
 * Foreground-сервис, запускающий cove-web-backend как дочерний процесс —
 * Android-аналог `desktop/app/web_server.py` (ROADMAP.md Фаза 13/"веб-морда
 * в Android"). Foreground обязателен: без него система убивает процесс
 * почти сразу после сворачивания приложения на фон.
 *
 * Бинарник упакован под видом `libcove_web_backend.so` в jniLibs
 * (scripts/build_web_backend_android.sh) — не JNA-загрузка, обычный
 * exec() через [ProcessBuilder], которому нужен настоящий файл на диске.
 * `android.packaging.jniLibs.useLegacyPackaging = true` в build.gradle.kts
 * обязателен — без него `applicationInfo.nativeLibraryDir` пуст (проверено
 * вживую на эмуляторе: AGP по умолчанию не извлекает .so на диск с
 * minSdk >= 23, грузит их прямо из APK).
 */
class WebServerService : Service() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var process: Process? = null

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopServer()
            return START_NOT_STICKY
        }

        val containerPath = intent?.getStringExtra(EXTRA_CONTAINER_PATH)
        val port = intent?.getIntExtra(EXTRA_PORT, DEFAULT_PORT) ?: DEFAULT_PORT
        if (containerPath == null) {
            stopSelf()
            return START_NOT_STICKY
        }

        startForeground(NOTIFICATION_ID, buildNotification(port))
        WebServerStatus.update(WebServerState.Starting)
        startServer(containerPath, port)
        // Не наша забота переживать смерть процесса системой и
        // перезапускаться самим — пользователь явно включает сервер заново
        // через настройки, как и на Desktop (никакого автозапуска).
        return START_NOT_STICKY
    }

    private fun startServer(containerPath: String, port: Int) {
        scope.launch {
            try {
                val frontendDir = extractFrontendAssets()
                val dataDir = File(filesDir, "web-tls").apply { mkdirs() }
                val binary = File(applicationInfo.nativeLibraryDir, "libcove_web_backend.so")
                if (!binary.exists()) {
                    WebServerStatus.update(WebServerState.Error("Бинарник веб-сервера не найден в APK"))
                    stopSelf()
                    return@launch
                }

                val builder = ProcessBuilder(
                    binary.absolutePath,
                    "--container", containerPath,
                    "--bind", "0.0.0.0:$port",
                    "--data-dir", dataDir.absolutePath,
                    "--frontend-dir", frontendDir.absolutePath,
                )
                builder.redirectErrorStream(true)
                val proc = builder.start()
                process = proc

                // Логи процесса — в logcat, а не DEVNULL (как когда-то было
                // на Desktop, пока это не аукнулось невидимыми ошибками —
                // см. web_server.py) — иначе диагностировать сбой запуска
                // здесь было бы нечем.
                scope.launch {
                    try {
                        proc.inputStream.bufferedReader().useLines { lines ->
                            lines.forEach { Log.i("CoveWebServer", it) }
                        }
                    } catch (_: IOException) {
                        // Ожидаемо: stopServer() вызывает proc.destroy(),
                        // который закрывает этот поток прямо во время
                        // блокирующего read() здесь, в ДРУГОЙ корутине —
                        // InterruptedIOException, не реальная ошибка.
                        // Раньше это исключение никем не ловилось и валило
                        // процесс приложения целиком (не только сервис) —
                        // найдено вживую: нажатие "Остановить" крашило всё
                        // приложение (FATAL EXCEPTION на
                        // DefaultDispatcher-worker, SupervisorJob не спасает
                        // от непойманного исключения в launch{}, только от
                        // отмены соседних корутин).
                    }
                }

                WebServerStatus.update(WebServerState.Running(port))

                // Ждём завершения процесса в фоне: если он упал сам (не по
                // нашей команде stopServer(), которая уже перевела статус в
                // Stopped до этого) — честно отражаем это в состоянии,
                // вместо того чтобы UI продолжал думать, что сервер жив.
                val exitCode = proc.waitFor()
                if (WebServerStatus.state.value is WebServerState.Running) {
                    WebServerStatus.update(WebServerState.Error("Процесс завершился неожиданно (код $exitCode)"))
                }
                stopSelf()
            } catch (e: Exception) {
                Log.e("CoveWebServer", "не удалось запустить веб-сервер", e)
                WebServerStatus.update(WebServerState.Error(e.message ?: "неизвестная ошибка"))
                stopSelf()
            }
        }
    }

    /** `--frontend-dir` читает с диска, не из APK — извлекаем 3 маленьких
     * файла из assets (см. build.gradle.kts: assets.srcDirs указывает прямо
     * на web/frontend, без дублирования исходников) при каждом запуске —
     * дёшево (десятки КБ) и гарантирует, что раздаётся версия именно из
     * установленного APK, а не устаревшая копия с прошлой сборки. */
    private fun extractFrontendAssets(): File {
        val dir = File(filesDir, "web-frontend").apply { mkdirs() }
        for (name in listOf("index.html", "app.js", "style.css")) {
            assets.open(name).use { input ->
                File(dir, name).outputStream().use { output -> input.copyTo(output) }
            }
        }
        return dir
    }

    private fun stopServer() {
        val proc = process
        process = null
        WebServerStatus.update(WebServerState.Stopped)
        if (proc != null) {
            scope.launch {
                // Тот же паттерн, что Desktop WebServerManager: сначала
                // мягко (destroy() ~ SIGTERM), даём время на честный
                // shutdown, и только если не откликнулся — принудительно.
                proc.destroy()
                val exited = withContext(Dispatchers.IO) {
                    try {
                        proc.waitFor(5, TimeUnit.SECONDS)
                    } catch (_: InterruptedException) {
                        false
                    }
                }
                if (!exited) proc.destroyForcibly()
            }
        }
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    override fun onDestroy() {
        process?.destroyForcibly()
        process = null
        WebServerStatus.update(WebServerState.Stopped)
        super.onDestroy()
    }

    private fun buildNotification(port: Int): Notification {
        ensureChannel()
        val stopIntent = Intent(this, WebServerService::class.java).apply { action = ACTION_STOP }
        val stopPendingIntent = PendingIntent.getService(
            this, 0, stopIntent, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val openIntent = Intent(this, MainActivity::class.java)
        val openPendingIntent = PendingIntent.getActivity(
            this, 0, openIntent, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("Cove: веб-доступ включён")
            .setContentText("Порт $port — открыть приложение или остановить")
            .setSmallIcon(android.R.drawable.ic_menu_share)
            .setContentIntent(openPendingIntent)
            .addAction(0, "Остановить", stopPendingIntent)
            .setOngoing(true)
            .build()
    }

    private fun ensureChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val manager = getSystemService(NotificationManager::class.java)
            if (manager.getNotificationChannel(CHANNEL_ID) == null) {
                val channel = NotificationChannel(
                    CHANNEL_ID, "Веб-доступ", NotificationManager.IMPORTANCE_LOW,
                )
                manager.createNotificationChannel(channel)
            }
        }
    }

    companion object {
        const val DEFAULT_PORT = 8443

        fun start(context: Context, containerPath: String, port: Int) {
            val intent = Intent(context, WebServerService::class.java).apply {
                putExtra(EXTRA_CONTAINER_PATH, containerPath)
                putExtra(EXTRA_PORT, port)
            }
            context.startForegroundService(intent)
        }

        fun stop(context: Context) {
            val intent = Intent(context, WebServerService::class.java).apply {
                action = ACTION_STOP
            }
            context.startService(intent)
        }
    }
}
