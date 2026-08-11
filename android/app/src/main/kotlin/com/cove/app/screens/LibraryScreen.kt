package com.cove.app.screens

import android.net.Uri
import android.provider.OpenableColumns
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.Image
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Menu
import androidx.compose.material.icons.filled.Star
import androidx.compose.material.icons.outlined.Star
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DrawerValue
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalDrawerSheet
import androidx.compose.material3.ModalNavigationDrawer
import androidx.compose.material3.NavigationDrawerItem
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.rememberDrawerState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.DpOffset
import androidx.compose.ui.unit.dp
import com.cove.app.media.FileKind
import com.cove.app.media.categoryOf
import com.cove.app.media.decodeBitmap
import com.cove.app.media.exportForExternalOpen
import com.cove.app.media.generateThumbnailBytes
import com.cove.app.media.kindOf
import com.cove.app.media.launchExternalViewIntent
import com.cove.app.storage.ThemeMode
import java.io.File
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.joinAll
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import uniffi.cove_core_uniffi.AndroidContainer
import uniffi.cove_core_uniffi.AndroidException
import uniffi.cove_core_uniffi.FileEntry
import uniffi.cove_core_uniffi.SearchQuery

private data class FolderCrumb(val id: ULong, val name: String)

/** Раздел библиотеки — либо настоящее дерево папок (Root), либо
 * виртуальный срез поверх search() (Category/Favorites), как в desktop
 * (main_window.py SECTIONS, ROADMAP.md Фаза 10) — отдельного индекса под
 * ними нет, та же resident File Table в памяти. */
private sealed class Section(val title: String) {
    data object Root : Section("Библиотека")
    data class Category(val label: String, val category: String) : Section(label)
    data object Favorites : Section("Избранное")
}

private val DRAWER_CATEGORIES = listOf(
    "Фото" to "image",
    "Видео" to "video",
    "Документы" to "document",
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun LibraryScreen(
    container: AndroidContainer,
    containerPath: String,
    themeMode: ThemeMode,
    onThemeModeChange: (ThemeMode) -> Unit,
    onLogout: () -> Unit,
) {
    var showSettings by remember { mutableStateOf(false) }
    if (showSettings) {
        SettingsScreen(
            containerPath = containerPath,
            themeMode = themeMode,
            onThemeModeChange = onThemeModeChange,
            onBack = { showSettings = false },
        )
        return
    }

    // Просмотрщики (Фаза 14, доработка) — та же диспетчеризация по типу,
    // что и в desktop viewer_dialog.py: image/video/audio/text открываются
    // во встроенном просмотрщике, всё остальное (pdf, RAW и т.п.) честно
    // предлагает открыть во внешнем приложении вместо молчаливого тапа.
    var viewingFile by remember { mutableStateOf<FileEntry?>(null) }
    val openingFile = viewingFile
    if (openingFile != null) {
        when (kindOf(openingFile.name)) {
            FileKind.IMAGE -> ImageViewerScreen(container, openingFile, onBack = { viewingFile = null })
            FileKind.VIDEO, FileKind.AUDIO -> MediaViewerScreen(container, openingFile, onBack = { viewingFile = null })
            FileKind.TEXT, FileKind.MARKDOWN -> TextViewerScreen(container, openingFile, onBack = { viewingFile = null })
            FileKind.UNKNOWN -> Unit // не должно случиться — см. openFile() ниже
        }
        return
    }

    var section by remember { mutableStateOf<Section>(Section.Root) }
    var folderStack by remember { mutableStateOf(listOf(FolderCrumb(0uL, "Библиотека"))) }
    var entries by remember { mutableStateOf<List<FileEntry>>(emptyList()) }
    var loading by remember { mutableStateOf(true) }
    var error by remember { mutableStateOf<String?>(null) }
    var showNewFolderDialog by remember { mutableStateOf(false) }
    var fabMenuExpanded by remember { mutableStateOf(false) }
    var refreshKey by remember { mutableStateOf(0) }
    var exportTarget by remember { mutableStateOf<FileEntry?>(null) }
    var externalOpenTarget by remember { mutableStateOf<FileEntry?>(null) }
    // Кэш декодированных миниатюр на время сессии экрана — без него каждый
    // повторный вход строки фото в композицию (например, при скролле назад)
    // заново гонял бы decode+readAt.
    val thumbnailCache = remember { mutableStateMapOf<ULong, ImageBitmap>() }
    val scope = rememberCoroutineScope()
    val context = LocalContext.current
    val drawerState = rememberDrawerState(initialValue = DrawerValue.Closed)

    val currentFolder = folderStack.last()

    // Незавершённые операции с container (импорт/создание папки/удаление и
    // т.п.) — "Выход" обязан дождаться их ПЕРЕД close(), иначе возможна
    // настоящая гонка: пользователь запускает импорт (SAF-чтение + запись в
    // File Table — не мгновенно для больших файлов), тут же жмёт "Выход" —
    // close() мог успеть отработать раньше, чем импорт домутировал File
    // Table, и это молча теряло файл (AndroidContainer.close_container()
    // забирает contener из Mutex<Option<_>>, следующий вызов импорта просто
    // получает AndroidError.Closed — а экран к этому моменту уже сменился
    // на Welcome, поэтому даже эта ошибка никогда не была видна). Найдено
    // по жалобе пользователя: "загрузил файлы, вышел, зашёл — пусто".
    val pendingWrites = remember { mutableStateListOf<Job>() }
    fun launchWrite(block: suspend () -> Unit) {
        lateinit var job: Job
        job = scope.launch {
            try {
                block()
            } finally {
                pendingWrites.remove(job)
            }
        }
        pendingWrites.add(job)
    }

    fun refresh() {
        refreshKey++
    }

    fun openFile(entry: FileEntry) {
        if (kindOf(entry.name) == FileKind.UNKNOWN) {
            externalOpenTarget = entry
        } else {
            viewingFile = entry
        }
    }

    fun selectSection(target: Section) {
        section = target
        folderStack = listOf(FolderCrumb(0uL, "Библиотека"))
        scope.launch { drawerState.close() }
    }

    // SAF (Storage Access Framework) — на Android (Scoped Storage, API 29+)
    // нет прямого доступа к произвольным путям файловой системы, только
    // через content://-URI, которые выдаёт система после выбора файла
    // пользователем. GetContent открывает системный пикер и отдаёт
    // временный доступ на чтение к выбранному файлу.
    val importLauncher = rememberLauncherForActivityResult(ActivityResultContracts.GetContent()) { uri: Uri? ->
        if (uri == null) return@rememberLauncherForActivityResult
        launchWrite {
            try {
                val name = queryDisplayName(uri, context) ?: uri.lastPathSegment ?: "imported_file"
                withContext(Dispatchers.IO) {
                    // Потоковое копирование в cacheDir вместо readBytes() в
                    // ByteArray целиком: на больших файлах (сотни МБ) второй
                    // вариант падает с OutOfMemoryError — heap growth limit
                    // Dalvik/ART (~192-256МБ) намного меньше, чем размер
                    // файла, а container.importFile(path) в Core читает файл
                    // блоками через File::open, не требуя буферизации.
                    // Core::import_file берёт имя файла из последнего
                    // компонента пути — отдельная поддиректория на каждый
                    // импорт нужна, чтобы temp-файл назывался ровно как
                    // оригинал (иначе в библиотеке файл сохранится под
                    // техническим именем).
                    val importDir = File(context.cacheDir, "imports/${System.nanoTime()}").apply { mkdirs() }
                    try {
                        // name приходит от content-провайдера (недоверенный
                        // источник) — берём только последний компонент пути,
                        // чтобы "../"-подобное имя не вывело файл за пределы
                        // importDir.
                        val safeName = File(name).name.ifEmpty { "imported_file" }
                        val tempFile = File(importDir, safeName)
                        context.contentResolver.openInputStream(uri)?.use { input ->
                            tempFile.outputStream().use { output -> input.copyTo(output) }
                        } ?: throw IllegalStateException("не удалось открыть файл")
                        container.importFile(tempFile.absolutePath, currentFolder.id)
                    } finally {
                        importDir.deleteRecursively()
                    }
                }
                refresh()
            } catch (e: Exception) {
                error = "Не удалось импортировать файл: ${e.message}"
            }
        }
    }

    // CreateDocument даёт content://-URI для записи в выбранное пользователем
    // место (Загрузки, Google Drive и т.п.) — сам путь на диске приложению
    // не виден, только этот URI.
    val exportLauncher = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("*/*")) { uri: Uri? ->
        val target = exportTarget
        exportTarget = null
        if (uri == null || target == null) return@rememberLauncherForActivityResult
        launchWrite {
            try {
                withContext(Dispatchers.IO) {
                    // Файл целиком в память за один readAt — тот же осознанный
                    // компромисс MVP, что и в web/backend (без Range нет смысла
                    // для локального экспорта), задокументирован там же.
                    val data = container.readAt(target.fileId, 0uL, target.size.toUInt())
                    context.contentResolver.openOutputStream(uri)?.use { it.write(data) }
                        ?: throw IllegalStateException("не удалось открыть место назначения")
                }
            } catch (e: Exception) {
                error = "Не удалось экспортировать файл: ${e.message}"
            }
        }
    }

    LaunchedEffect(exportTarget) {
        exportTarget?.let { exportLauncher.launch(it.name) }
    }

    LaunchedEffect(section, currentFolder.id, refreshKey) {
        loading = true
        try {
            entries = withContext(Dispatchers.IO) {
                when (val current = section) {
                    is Section.Root -> container.listDir(currentFolder.id)
                    // Та же навигация по папкам, что и в Root, с фильтром на
                    // клиенте. Папки фильтруются по folderCategory — тегу,
                    // который папка получает один раз при создании (в какой
                    // вкладке нажали "+", та категория и закрепляется, не
                    // пересчитывается по содержимому — по прямому запросу
                    // пользователя: папка, созданная в "Фото", не должна
                    // "утекать" в "Видео"/"Документы", даже если разово в
                    // неё попадёт видео). Файлы — по фактическому
                    // расширению, как и раньше.
                    is Section.Category -> container.listDir(currentFolder.id)
                        .filter {
                            (it.isFolder && it.folderCategory == current.category) ||
                                (!it.isFolder && categoryOf(it.name) == current.category)
                        }
                    is Section.Favorites -> container.search(SearchQuery(favorite = true))
                }
            }
            error = null
        } catch (e: AndroidException) {
            error = "Не удалось загрузить список: ${e.message}"
        }
        loading = false
    }

    ModalNavigationDrawer(
        drawerState = drawerState,
        drawerContent = {
            ModalDrawerSheet {
                Text(
                    "Cove",
                    style = MaterialTheme.typography.titleLarge,
                    modifier = Modifier.padding(24.dp),
                )
                NavigationDrawerItem(
                    label = { Text("Библиотека") },
                    selected = section is Section.Root,
                    onClick = { selectSection(Section.Root) },
                    modifier = Modifier.padding(horizontal = 12.dp),
                )
                for ((label, category) in DRAWER_CATEGORIES) {
                    NavigationDrawerItem(
                        label = { Text(label) },
                        selected = (section as? Section.Category)?.category == category,
                        onClick = { selectSection(Section.Category(label, category)) },
                        modifier = Modifier.padding(horizontal = 12.dp),
                    )
                }
                NavigationDrawerItem(
                    label = { Text("Избранное") },
                    selected = section is Section.Favorites,
                    onClick = { selectSection(Section.Favorites) },
                    modifier = Modifier.padding(horizontal = 12.dp),
                )
                HorizontalDivider(modifier = Modifier.padding(vertical = 12.dp))
                NavigationDrawerItem(
                    label = { Text("Настройки") },
                    selected = false,
                    onClick = {
                        scope.launch { drawerState.close() }
                        showSettings = true
                    },
                    modifier = Modifier.padding(horizontal = 12.dp),
                )
            }
        },
    ) {
        Scaffold(
            topBar = {
                TopAppBar(
                    title = {
                        Text(
                            when (section) {
                                is Section.Root -> folderStack.joinToString(" / ") { it.name }
                                is Section.Category -> section.title + " / " + folderStack.joinToString(" / ") { it.name }
                                is Section.Favorites -> section.title
                            },
                        )
                    },
                    navigationIcon = {
                        IconButton(onClick = { scope.launch { drawerState.open() } }) {
                            Icon(Icons.Filled.Menu, contentDescription = "Разделы")
                        }
                    },
                    actions = {
                        if ((section is Section.Root || section is Section.Category) && folderStack.size > 1) {
                            TextButton(onClick = { folderStack = folderStack.dropLast(1) }) {
                                Text("Назад")
                            }
                        }
                        TextButton(onClick = {
                            // create_folder/delete_file и т.п. в Core только мутируют
                            // File Table в памяти — реальный commit на диск происходит
                            // в close(). Если не дождаться его перед сменой экрана,
                            // процесс может быть убит раньше, чем commit случится, и
                            // несохранённые изменения потеряются (найдено вживую: после
                            // удаления папки и быстрого выхода она "возвращалась").
                            //
                            // Мало дождаться самого close() — сначала обязательно
                            // дождаться ВСЕХ ещё не завершившихся launchWrite()
                            // (например, импорт файла, запущенный за миг до тапа на
                            // "Выход"): иначе close() может выполниться раньше и
                            // забрать container из Mutex, и незавершённый импорт
                            // молча потеряет файл (см. комментарий у pendingWrites).
                            scope.launch {
                                pendingWrites.toList().joinAll()
                                withContext(Dispatchers.IO) { container.closeContainer() }
                                onLogout()
                            }
                        }) { Text("Выход") }
                    },
                )
            },
            floatingActionButton = {
                // Доступно во всех разделах. Root и Category — настоящая
                // навигация по папкам (currentFolder.id = folderStack.last().id),
                // поэтому "Новая папка"/"Загрузить файл" в Category кладут
                // результат в текущую (под-)папку этой категории, а не в
                // корень. У Favorites своей "текущей папки" нет — там
                // currentFolder.id всегда 0 (folderStack сбрасывается в
                // selectSection() и никогда не растёт, т.к. клик по папке
                // обрабатывается только для Root/Category выше).
                Box {
                    FloatingActionButton(onClick = { fabMenuExpanded = true }) {
                        Icon(Icons.Filled.Add, contentDescription = "Добавить")
                    }
                    DropdownMenu(
                        expanded = fabMenuExpanded,
                        onDismissRequest = { fabMenuExpanded = false },
                        // Разворачивается влево и вверх от кнопки, а не вниз-вправо
                        // по умолчанию — так пункты меню не оказываются под
                        // системной панелью жестов внизу экрана. Смещение
                        // небольшое, чтобы меню оставалось рядом с кнопкой,
                        // а не отрывалось от неё в сторону.
                        offset = DpOffset(x = 0.dp, y = (-16).dp),
                        modifier = Modifier.widthIn(min = 220.dp),
                        shape = RoundedCornerShape(20.dp),
                    ) {
                        DropdownMenuItem(
                            text = { Text("Новая папка", style = MaterialTheme.typography.titleMedium) },
                            onClick = {
                                fabMenuExpanded = false
                                showNewFolderDialog = true
                            },
                        )
                        DropdownMenuItem(
                            text = { Text("Загрузить файл", style = MaterialTheme.typography.titleMedium) },
                            onClick = {
                                fabMenuExpanded = false
                                importLauncher.launch("*/*")
                            },
                        )
                    }
                }
            },
        ) { padding ->
            Box(modifier = Modifier.fillMaxSize().padding(padding)) {
                when {
                    loading -> CircularProgressIndicator(modifier = Modifier.align(Alignment.Center))
                    error != null -> Text(
                        error!!,
                        color = MaterialTheme.colorScheme.error,
                        modifier = Modifier.align(Alignment.Center).padding(24.dp),
                    )
                    entries.isEmpty() -> Text(
                        "Здесь пока пусто",
                        style = MaterialTheme.typography.bodyMedium,
                        modifier = Modifier.align(Alignment.Center),
                    )
                    else -> LazyColumn(modifier = Modifier.fillMaxSize()) {
                        // key должен быть Bundle-совместимым типом (для saveable state) —
                        // ULong (fileId) им не является, отсюда был реальный крэш
                        // "Type of the key ... is not supported" при непустом списке.
                        items(entries, key = { it.fileId.toLong() }) { entry ->
                            FileRow(
                                container = container,
                                entry = entry,
                                thumbnailCache = thumbnailCache,
                                onClick = {
                                    if (entry.isFolder) {
                                        if (section is Section.Root || section is Section.Category) {
                                            folderStack = folderStack + FolderCrumb(entry.fileId, entry.name)
                                        }
                                    } else {
                                        openFile(entry)
                                    }
                                },
                                onToggleFavorite = {
                                    launchWrite {
                                        try {
                                            withContext(Dispatchers.IO) {
                                                container.setFavorite(entry.fileId, !entry.favorite)
                                            }
                                            refresh()
                                        } catch (_: AndroidException) {
                                            // избранное — не критичная операция, тихо игнорируем сбой UI-стороны
                                        }
                                    }
                                },
                                onDelete = {
                                    launchWrite {
                                        try {
                                            withContext(Dispatchers.IO) { container.deleteFile(entry.fileId) }
                                            refresh()
                                        } catch (e: AndroidException) {
                                            error = "Не удалось удалить: ${e.message}"
                                        }
                                    }
                                },
                                onExport = { exportTarget = entry },
                            )
                        }
                    }
                }
            }

            if (showNewFolderDialog) {
                NewFolderDialog(
                    onDismiss = { showNewFolderDialog = false },
                    onConfirm = { name ->
                        showNewFolderDialog = false
                        // (section as? Section.Category)?.category — null для
                        // Root (папка ни к чему не привязана, видна только в
                        // "Библиотеке") и категория для Category-разделов —
                        // ровно то, что нужно createFolder() для тега (см.
                        // FileEntry.folderCategory).
                        val category = (section as? Section.Category)?.category
                        launchWrite {
                            try {
                                withContext(Dispatchers.IO) {
                                    container.createFolder(name, currentFolder.id, category)
                                }
                                refresh()
                            } catch (e: AndroidException) {
                                error = "Не удалось создать папку: ${e.message}"
                            }
                        }
                    },
                )
            }

            val unsupportedTarget = externalOpenTarget
            if (unsupportedTarget != null) {
                AlertDialog(
                    onDismissRequest = { externalOpenTarget = null },
                    title = { Text("Открыть во внешнем приложении?") },
                    text = {
                        Text(
                            "Для «${unsupportedTarget.name}» ещё нет встроенного просмотрщика в Cove. " +
                                "Открыть во внешнем приложении?",
                        )
                    },
                    confirmButton = {
                        TextButton(onClick = {
                            externalOpenTarget = null
                            launchWrite {
                                try {
                                    val uri = withContext(Dispatchers.IO) {
                                        exportForExternalOpen(context, container, unsupportedTarget)
                                    }
                                    launchExternalViewIntent(context, uri, unsupportedTarget.name)
                                } catch (e: Exception) {
                                    error = "Не удалось открыть файл: ${e.message}"
                                }
                            }
                        }) { Text("Открыть") }
                    },
                    dismissButton = {
                        TextButton(onClick = { externalOpenTarget = null }) { Text("Отмена") }
                    },
                )
            }
        }
    }
}

@Composable
private fun FileRow(
    container: AndroidContainer,
    entry: FileEntry,
    thumbnailCache: androidx.compose.runtime.snapshots.SnapshotStateMap<ULong, ImageBitmap>,
    onClick: () -> Unit,
    onToggleFavorite: () -> Unit,
    onDelete: () -> Unit,
    onExport: () -> Unit,
) {
    // Миниатюра — только для фото: находим уже сгенерированную (findThumbnail)
    // либо декодируем оригинал и генерируем новую через container.thumbnail()
    // (ROADMAP.md Фаза 8, доработка после того как обнаружилось, что на
    // Android миниатюры вообще не появлялись — Фазу 14 портировали без них).
    val isImage = !entry.isFolder && kindOf(entry.name) == FileKind.IMAGE
    LaunchedEffect(entry.fileId, isImage) {
        if (!isImage || thumbnailCache.containsKey(entry.fileId)) return@LaunchedEffect
        val bitmap = withContext(Dispatchers.IO) {
            try {
                val existingId = container.findThumbnail(entry.fileId)
                val pngBytes = if (existingId != null) {
                    container.readAt(existingId, 0uL, container.fileSize(existingId).toUInt())
                } else {
                    val original = container.readAt(entry.fileId, 0uL, entry.size.toUInt())
                    val generated = generateThumbnailBytes(original) ?: return@withContext null
                    container.thumbnail(entry.fileId, generated)
                    generated
                }
                decodeBitmap(pngBytes)
            } catch (_: Exception) {
                null
            }
        }
        if (bitmap != null) thumbnailCache[entry.fileId] = bitmap.asImageBitmap()
    }

    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(horizontal = 16.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        if (isImage) {
            val thumb = thumbnailCache[entry.fileId]
            Box(modifier = Modifier.size(48.dp)) {
                if (thumb != null) {
                    Image(
                        bitmap = thumb,
                        contentDescription = null,
                        contentScale = ContentScale.Crop,
                        modifier = Modifier.size(48.dp),
                    )
                } else {
                    Text("🖼", style = MaterialTheme.typography.headlineMedium)
                }
            }
            androidx.compose.foundation.layout.Spacer(modifier = Modifier.padding(start = 8.dp))
        }
        Column(modifier = Modifier.weight(1f)) {
            Text(
                if (entry.isFolder) "📁 ${entry.name}" else entry.name,
                style = MaterialTheme.typography.bodyLarge,
            )
            if (!entry.isFolder) {
                Text(friendlySize(entry.size), style = MaterialTheme.typography.bodySmall)
            }
        }
        if (!entry.isFolder) {
            IconButton(onClick = onToggleFavorite) {
                Icon(
                    if (entry.favorite) Icons.Filled.Star else Icons.Outlined.Star,
                    contentDescription = "Избранное",
                )
            }
            IconButton(onClick = onExport) {
                Text("⬇", style = MaterialTheme.typography.titleMedium)
            }
        }
        IconButton(onClick = onDelete) {
            Icon(Icons.Filled.Delete, contentDescription = "Удалить")
        }
    }
}

@Composable
private fun NewFolderDialog(onDismiss: () -> Unit, onConfirm: (String) -> Unit) {
    var name by remember { mutableStateOf("") }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Новая папка") },
        text = {
            OutlinedTextField(
                value = name,
                onValueChange = { name = it },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
        },
        confirmButton = {
            TextButton(onClick = { if (name.isNotBlank()) onConfirm(name.trim()) }) {
                Text("Создать")
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text("Отмена") }
        },
    )
}

/** SAF отдаёт content://-URI, а не файловый путь — оригинальное имя файла
 * достаётся только через cursor-запрос колонки DISPLAY_NAME. */
private fun queryDisplayName(uri: Uri, context: android.content.Context): String? {
    context.contentResolver.query(uri, null, null, null, null)?.use { cursor ->
        val nameIndex = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
        if (nameIndex >= 0 && cursor.moveToFirst()) {
            return cursor.getString(nameIndex)
        }
    }
    return null
}

private fun friendlySize(bytes: ULong): String {
    if (bytes < 1024uL) return "$bytes Б"
    val units = listOf("КБ", "МБ", "ГБ", "ТБ")
    var value = bytes.toDouble() / 1024.0
    var i = 0
    while (value >= 1024.0 && i < units.size - 1) {
        value /= 1024.0
        i++
    }
    return "%.1f %s".format(value, units[i])
}
