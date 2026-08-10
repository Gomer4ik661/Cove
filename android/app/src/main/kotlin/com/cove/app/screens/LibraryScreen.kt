package com.cove.app.screens

import android.net.Uri
import android.provider.OpenableColumns
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
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
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.DpOffset
import androidx.compose.ui.unit.dp
import com.cove.app.storage.ThemeMode
import kotlinx.coroutines.Dispatchers
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

    var section by remember { mutableStateOf<Section>(Section.Root) }
    var folderStack by remember { mutableStateOf(listOf(FolderCrumb(0uL, "Библиотека"))) }
    var entries by remember { mutableStateOf<List<FileEntry>>(emptyList()) }
    var loading by remember { mutableStateOf(true) }
    var error by remember { mutableStateOf<String?>(null) }
    var showNewFolderDialog by remember { mutableStateOf(false) }
    var fabMenuExpanded by remember { mutableStateOf(false) }
    var refreshKey by remember { mutableStateOf(0) }
    var exportTarget by remember { mutableStateOf<FileEntry?>(null) }
    val scope = rememberCoroutineScope()
    val context = LocalContext.current
    val drawerState = rememberDrawerState(initialValue = DrawerValue.Closed)

    val currentFolder = folderStack.last()

    fun refresh() {
        refreshKey++
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
        scope.launch {
            try {
                val name = queryDisplayName(uri, context) ?: uri.lastPathSegment ?: "imported_file"
                val bytes = withContext(Dispatchers.IO) {
                    context.contentResolver.openInputStream(uri)?.use { it.readBytes() }
                        ?: throw IllegalStateException("не удалось открыть файл")
                }
                withContext(Dispatchers.IO) { container.importFileFromBytes(name, currentFolder.id, bytes) }
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
        scope.launch {
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
                    is Section.Category -> container.search(SearchQuery(category = current.category))
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
                            if (section is Section.Root) folderStack.joinToString(" / ") { it.name }
                            else section.title,
                        )
                    },
                    navigationIcon = {
                        IconButton(onClick = { scope.launch { drawerState.open() } }) {
                            Icon(Icons.Filled.Menu, contentDescription = "Разделы")
                        }
                    },
                    actions = {
                        if (section is Section.Root && folderStack.size > 1) {
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
                            scope.launch {
                                withContext(Dispatchers.IO) { container.closeContainer() }
                                onLogout()
                            }
                        }) { Text("Выход") }
                    },
                )
            },
            floatingActionButton = {
                // Доступно во всех разделах, не только в дереве папок — у
                // виртуальных разделов (категория/избранное) нет своей
                // "текущей папки", поэтому и "Новая папка", и "Загрузить
                // файл" в них кладут результат в корень библиотеки
                // (currentFolder.id всегда 0 вне Section.Root — folderStack
                // сбрасывается в selectSection()).
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
                                entry = entry,
                                onClick = {
                                    if (entry.isFolder && section is Section.Root) {
                                        folderStack = folderStack + FolderCrumb(entry.fileId, entry.name)
                                    }
                                },
                                onToggleFavorite = {
                                    scope.launch {
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
                                    scope.launch {
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
                        scope.launch {
                            try {
                                withContext(Dispatchers.IO) { container.createFolder(name, currentFolder.id) }
                                refresh()
                            } catch (e: AndroidException) {
                                error = "Не удалось создать папку: ${e.message}"
                            }
                        }
                    },
                )
            }
        }
    }
}

@Composable
private fun FileRow(
    entry: FileEntry,
    onClick: () -> Unit,
    onToggleFavorite: () -> Unit,
    onDelete: () -> Unit,
    onExport: () -> Unit,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(enabled = entry.isFolder, onClick = onClick)
            .padding(horizontal = 16.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
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
