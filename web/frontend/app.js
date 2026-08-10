// Минимальный vanilla JS фронтенд (Фаза 13, ROADMAP.md) — без сборки, без
// npm, отдаётся тем же Axum-сервером как статика. ARCHITECTURE.md изначально
// набрасывал Svelte/TS, но для MVP это лишний build-tooling overhead без
// реальной выгоды при таком объёме UI — решение задокументировано в ROADMAP.

const state = {
  csrfToken: null,
  username: null,
  role: null,
  view: "library", // library | favorites | trash | search
  folderStack: [{ id: 0, name: "Библиотека" }],
  searchQuery: "",
};

const $ = (sel) => document.querySelector(sel);

async function api(path, options = {}) {
  const opts = { credentials: "same-origin", ...options };
  const method = (opts.method || "GET").toUpperCase();
  if (method !== "GET" && method !== "HEAD") {
    opts.headers = { ...(opts.headers || {}), "X-CSRF-Token": state.csrfToken || "" };
  }
  const res = await fetch(path, opts);
  if (!res.ok) {
    let msg = res.statusText;
    try {
      const body = await res.json();
      msg = body.error || msg;
    } catch (_) {
      /* тело не JSON — оставляем statusText */
    }
    const err = new Error(msg);
    err.status = res.status;
    throw err;
  }
  const contentType = res.headers.get("content-type") || "";
  if (contentType.includes("application/json")) return res.json();
  return null;
}

function friendlySize(bytes) {
  if (bytes < 1024) return `${bytes} Б`;
  const units = ["КБ", "МБ", "ГБ", "ТБ"];
  let v = bytes / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(1)} ${units[i]}`;
}

function iconFor(entry) {
  if (entry.is_folder) return "📁";
  const mime = entry.mime_hint || "";
  if (mime.startsWith("image/")) return "🖼️";
  if (mime.startsWith("video/")) return "🎬";
  if (mime.startsWith("audio/")) return "🎵";
  if (mime.startsWith("text/")) return "📄";
  return "📦";
}

// ---------- Login ----------

$("#login-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const username = $("#login-username").value;
  const password = $("#login-password").value;
  $("#login-error").hidden = true;
  try {
    const data = await api("/api/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
    });
    state.csrfToken = data.csrf_token;
    state.username = data.username;
    state.role = data.role;
    showApp();
  } catch (err) {
    const msg =
      err.status === 429
        ? "Слишком много попыток входа. Попробуйте позже."
        : "Неверное имя пользователя или пароль.";
    $("#login-error").textContent = msg;
    $("#login-error").hidden = false;
  }
});

$("#logout-btn").addEventListener("click", async () => {
  try {
    await api("/api/logout", { method: "POST" });
  } catch (_) {
    /* сессия уже могла истечь — всё равно возвращаемся на экран входа */
  }
  state.csrfToken = null;
  $("#app-screen").hidden = true;
  $("#login-screen").hidden = false;
  $("#login-password").value = "";
});

function showApp() {
  $("#login-screen").hidden = true;
  $("#app-screen").hidden = false;
  $("#whoami").textContent = `${state.username} (${state.role})`;
  state.folderStack = [{ id: 0, name: "Библиотека" }];
  state.view = "library";
  refresh();
}

// ---------- Навигация ----------

document.querySelectorAll(".nav-item").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".nav-item").forEach((b) => b.classList.remove("active"));
    btn.classList.add("active");
    state.view = btn.dataset.view;
    state.folderStack = [{ id: 0, name: "Библиотека" }];
    $("#search-input").value = "";
    state.searchQuery = "";
    refresh();
  });
});

$("#search-input").addEventListener("input", (e) => {
  state.searchQuery = e.target.value.trim();
  if (state.searchQuery) {
    state.view = "search";
  } else {
    state.view = "library";
    document.querySelectorAll(".nav-item").forEach((b) => b.classList.remove("active"));
    $('.nav-item[data-view="library"]').classList.add("active");
  }
  refresh();
});

function renderBreadcrumb() {
  const bc = $("#breadcrumb");
  bc.innerHTML = "";
  if (state.view !== "library") {
    const label = { favorites: "Избранное", trash: "Корзина", search: "Поиск" }[state.view];
    const span = document.createElement("span");
    span.className = "current";
    span.textContent = label;
    bc.appendChild(span);
    return;
  }
  state.folderStack.forEach((f, idx) => {
    const span = document.createElement("span");
    span.textContent = f.name;
    if (idx === state.folderStack.length - 1) {
      span.className = "current";
    } else {
      span.addEventListener("click", () => {
        state.folderStack = state.folderStack.slice(0, idx + 1);
        refresh();
      });
    }
    bc.appendChild(span);
    if (idx < state.folderStack.length - 1) {
      bc.appendChild(document.createTextNode(" / "));
    }
  });
}

function currentFolderId() {
  return state.folderStack[state.folderStack.length - 1].id;
}

// ---------- Загрузка списка ----------

async function refresh() {
  renderBreadcrumb();
  $("#toolbar").hidden = state.view !== "library";
  $("#content-error").hidden = true;
  try {
    let entries;
    if (state.view === "library") {
      entries = await api(`/api/library?folder_id=${currentFolderId()}`);
    } else if (state.view === "trash") {
      entries = await api("/api/trash");
    } else if (state.view === "favorites") {
      entries = await api("/api/search?favorite=true");
    } else {
      entries = await api(`/api/search?name_contains=${encodeURIComponent(state.searchQuery)}`);
    }
    renderGrid(entries);
  } catch (err) {
    if (err.status === 401) {
      state.csrfToken = null;
      $("#app-screen").hidden = true;
      $("#login-screen").hidden = false;
      return;
    }
    $("#content-error").textContent = "Не удалось загрузить список: " + err.message;
    $("#content-error").hidden = false;
  }
}

function renderGrid(entries) {
  const grid = $("#file-grid");
  grid.innerHTML = "";
  $("#empty-hint").hidden = entries.length !== 0;
  for (const entry of entries) {
    grid.appendChild(renderCard(entry));
  }
}

function renderCard(entry) {
  const card = document.createElement("div");
  card.className = "file-card";

  const icon = document.createElement("div");
  icon.className = "icon";
  icon.textContent = iconFor(entry);
  card.appendChild(icon);

  const name = document.createElement("div");
  name.className = "name";
  name.title = entry.name;
  name.textContent = entry.name;
  card.appendChild(name);

  const meta = document.createElement("div");
  meta.className = "meta";
  meta.textContent = entry.is_folder ? "Папка" : friendlySize(entry.size);
  card.appendChild(meta);

  card.addEventListener("click", (e) => {
    if (e.target.closest(".actions")) return;
    if (entry.is_folder && state.view === "library") {
      state.folderStack.push({ id: entry.file_id, name: entry.name });
      refresh();
    } else if (!entry.is_folder) {
      window.open(`/api/files/${entry.file_id}/download`, "_blank");
    }
  });

  const actions = document.createElement("div");
  actions.className = "actions";

  if (state.view === "trash") {
    actions.appendChild(actionButton("Восстановить", async () => {
      await api(`/api/files/${entry.file_id}/restore`, { method: "POST" });
      refresh();
    }));
  } else {
    if (!entry.is_folder) {
      const favBtn = actionButton(entry.favorite ? "★" : "☆", async () => {
        await api(`/api/files/${entry.file_id}/favorite`, {
          method: "PATCH",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ favorite: !entry.favorite }),
        });
        refresh();
      });
      favBtn.classList.add("favorite");
      if (entry.favorite) favBtn.classList.add("active");
      actions.appendChild(favBtn);
    }
    actions.appendChild(actionButton("Переименовать", async () => {
      const name = await showPrompt("Новое имя:", entry.name);
      if (!name || name === entry.name) return;
      await api(`/api/files/${entry.file_id}/rename`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name }),
      });
      refresh();
    }));
    const delBtn = actionButton("Удалить", async () => {
      await api(`/api/files/${entry.file_id}`, { method: "DELETE" });
      refresh();
    });
    delBtn.classList.add("danger");
    actions.appendChild(delBtn);
  }

  card.appendChild(actions);
  return card;
}

// Собственное модальное окно вместо window.prompt(): нативные диалоги
// блокируют вкладку целиком и плохо ведут себя в некоторых окружениях
// (замечено при тестировании — CDP-браузер молча отклонял prompt()).
function showPrompt(title, defaultValue = "") {
  const overlay = $("#modal-overlay");
  const input = $("#modal-input");
  $("#modal-title").textContent = title;
  input.value = defaultValue;
  overlay.hidden = false;
  input.focus();
  input.select();

  return new Promise((resolve) => {
    function cleanup(result) {
      overlay.hidden = true;
      $("#modal-form").removeEventListener("submit", onSubmit);
      $("#modal-cancel").removeEventListener("click", onCancel);
      resolve(result);
    }
    function onSubmit(e) {
      e.preventDefault();
      cleanup(input.value.trim() || null);
    }
    function onCancel() {
      cleanup(null);
    }
    $("#modal-form").addEventListener("submit", onSubmit);
    $("#modal-cancel").addEventListener("click", onCancel);
  });
}

function actionButton(label, onClick) {
  const btn = document.createElement("button");
  btn.type = "button";
  btn.textContent = label;
  btn.addEventListener("click", async (e) => {
    e.stopPropagation();
    try {
      await onClick();
    } catch (err) {
      alert("Ошибка: " + err.message);
    }
  });
  return btn;
}

// ---------- Новая папка / загрузка файлов ----------

$("#new-folder-btn").addEventListener("click", async () => {
  const name = await showPrompt("Название папки:");
  if (!name) return;
  try {
    await api("/api/folders", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name, parent_id: currentFolderId() }),
    });
    refresh();
  } catch (err) {
    alert("Не удалось создать папку: " + err.message);
  }
});

$("#upload-input").addEventListener("change", async (e) => {
  const files = Array.from(e.target.files || []);
  e.target.value = "";
  for (const file of files) {
    const form = new FormData();
    form.append("parent_id", String(currentFolderId()));
    form.append("file", file);
    try {
      await api("/api/upload", { method: "POST", body: form });
    } catch (err) {
      alert(`Не удалось загрузить "${file.name}": ${err.message}`);
    }
  }
  refresh();
});

// ---------- Проверка уже активной сессии при перезагрузке страницы ----------
// Кука сессии переживает reload, но csrf_token живёт только в памяти этой
// вкладки — если он потерян (F5), просим войти заново. Это осознанный
// компромисс простоты для MVP-фронтенда, а не недосмотр: держать
// csrf_token в sessionStorage было бы чуть удобнее, но так он ни разу не
// касается постоянного хранилища браузера.
