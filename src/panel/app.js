const state = {
  categories: [],
  tasks: [],
  analysts: [],
  colors: new Map(),
  filters: {
    status: 'all',
    search: '',
    categories: new Set(),
    showCompleted: false
  },
  viewMode: 'category',
  reminders: new Map(),
  autoRefresh: true,
  lastUpdate: null,
  settings: {
    whatsappSession: '',
    analystName: '',
    googleSheetId: '',
    googleClientEmail: '',
    googlePrivateKey: '',
    googleProjectId: ''
  },
  status: {
    storage: 'local',
    googleConfigured: false,
    whatsapp: { active: false, session: '' },
    analystName: ''
  }
};

let autoRefreshHandle;
let settingsFeedbackTimeout;
let realtimeSocket;
let realtimeReconnectTimeout;

const summaryEl = document.getElementById('summary');
const boardEl = document.getElementById('board');
const insightsEl = document.getElementById('insights');
const refreshButton = document.getElementById('refreshTasks');
const lastUpdateEl = document.getElementById('lastUpdate');
const taskTemplate = document.getElementById('task-card');
const searchInput = document.getElementById('searchTasks');
const statusFiltersEl = document.getElementById('statusFilters');
const categoryFiltersEl = document.getElementById('categoryFilters');
const viewToggleEl = document.getElementById('viewToggle');
const showCompletedInput = document.getElementById('showCompleted');
const autoRefreshInput = document.getElementById('autoRefresh');
const openSettingsButton = document.getElementById('openSettings');
const settingsOverlay = document.getElementById('settingsOverlay');
const closeSettingsButton = document.getElementById('closeSettings');
const settingsForm = document.getElementById('settingsForm');
const settingsFeedbackEl = document.getElementById('settingsFeedback');
const settingsStorageInfo = document.getElementById('settingsStorageInfo');
const settingsWhatsappInfo = document.getElementById('settingsWhatsappInfo');

function isRealtimeConnected() {
  return Boolean(realtimeSocket && realtimeSocket.readyState === WebSocket.OPEN);
}

function isRealtimeConnecting() {
  return Boolean(realtimeSocket && realtimeSocket.readyState === WebSocket.CONNECTING);
}

function updateLastUpdate(timestamp = Date.now()) {
  state.lastUpdate = timestamp;
  if (!lastUpdateEl) {
    return;
  }
  const formatted = new Date(timestamp).toLocaleTimeString('pt-BR');
  lastUpdateEl.textContent = `Última atualização: ${formatted}`;
}

async function fetchJson(url, options) {
  const response = await fetch(url, options);
  if (!response.ok) {
    const payload = await response.json().catch(() => ({}));
    const message = payload.message || 'Não foi possível completar a operação.';
    throw new Error(message);
  }
  return response.json();
}

function decodePrivateKey(value) {
  return (value || '').replace(/\\n/g, '\n');
}

function encodePrivateKey(value) {
  return (value || '').replace(/\r?\n/g, '\\n');
}

function applySystemStatus(status = {}) {
  const whatsapp = status.whatsapp || {};
  state.status = {
    storage: status.storage || 'local',
    googleConfigured: Boolean(status.googleConfigured),
    whatsapp: {
      active: Boolean(whatsapp.active),
      session: whatsapp.session || ''
    },
    analystName: status.analystName || state.settings.analystName || ''
  };
  updateSettingsSummaryInfo();
}

function parseTaskDate(raw) {
  if (!raw) {
    return null;
  }
  const [datePart, timePart = '00:00'] = raw.split(' ');
  const [day, month, year] = datePart.split('/').map(Number);
  const [hour = 0, minute = 0] = timePart.split(':').map(Number);
  if ([day, month, year].some(Number.isNaN)) {
    return null;
  }
  const parsed = new Date(year, (month || 1) - 1, day || 1, hour, minute);
  return Number.isNaN(parsed.getTime()) ? null : parsed;
}

function getTaskAgeInMinutes(task) {
  const createdAt = parseTaskDate(task.date);
  if (!createdAt) {
    return 0;
  }
  const diff = Date.now() - createdAt.getTime();
  return Math.max(0, Math.floor(diff / 60000));
}

function formatDuration(minutes) {
  if (!minutes) {
    return 'Recente';
  }
  const days = Math.floor(minutes / 1440);
  const hours = Math.floor((minutes % 1440) / 60);
  const mins = minutes % 60;
  const chunks = [];
  if (days) {
    chunks.push(`${days}d`);
  }
  if (hours) {
    chunks.push(`${hours}h`);
  }
  if (mins && chunks.length < 2) {
    chunks.push(`${mins}min`);
  }
  return chunks.join(' ') || 'Recente';
}

function formatDateTime(raw) {
  const date = parseTaskDate(raw);
  if (!date) {
    return 'Data não informada';
  }
  return `Recebido em ${date.toLocaleDateString('pt-BR')} às ${date
    .toLocaleTimeString('pt-BR', { hour: '2-digit', minute: '2-digit' })
    .padStart(5, '0')}`;
}

function formatReminderTime(dueAt) {
  const remaining = Math.max(0, dueAt - Date.now());
  const minutes = Math.round(remaining / 60000);
  if (minutes <= 1) {
    return 'Lembrete em breve';
  }
  return `Lembrete em ${formatDuration(minutes)}`;
}

function isToday(raw) {
  const date = parseTaskDate(raw);
  if (!date) {
    return false;
  }
  const now = new Date();
  return (
    date.getFullYear() === now.getFullYear() &&
    date.getMonth() === now.getMonth() &&
    date.getDate() === now.getDate()
  );
}

function determinePriority(task) {
  if (task.status === 'Concluído') {
    return { label: 'Finalizado', level: 'completed' };
  }
  const age = getTaskAgeInMinutes(task);
  if (age >= 720) {
    return { label: 'Crítico', level: 'critical' };
  }
  if (age >= 480) {
    return { label: 'Urgente', level: 'warning' };
  }
  if (age >= 180) {
    return { label: 'Atentar', level: 'attention' };
  }
  return { label: 'Dentro do SLA', level: 'normal' };
}

function getStatusClass(status) {
  if (!status) {
    return 'status-open';
  }
  const normalized = status.toLowerCase();
  if (normalized.includes('concl')) {
    return 'status-completed';
  }
  if (normalized.includes('andamento') || normalized.includes('processo')) {
    return 'status-progress';
  }
  if (normalized.includes('pend') || normalized.includes('aguard')) {
    return 'status-waiting';
  }
  return 'status-open';
}

function getFilteredTasks() {
  const { status, search, categories, showCompleted } = state.filters;
  const searchTerm = search.trim().toLowerCase();
  return state.tasks.filter((task) => {
    if (!showCompleted && task.status === 'Concluído') {
      return false;
    }
    if (status !== 'all' && task.status !== status) {
      return false;
    }
    if (categories.size > 0 && !categories.has(task.category || 'Sem categoria')) {
      return false;
    }
    if (!searchTerm) {
      return true;
    }
    const haystack = [task.number, task.message, task.category, task.analyst, task.status]
      .filter(Boolean)
      .join(' ')
      .toLowerCase();
    return haystack.includes(searchTerm);
  });
}

function renderSummary() {
  summaryEl.innerHTML = '';
  const total = state.tasks.length;
  const active = state.tasks.filter((task) => task.status !== 'Concluído').length;
  const concluded = state.tasks.filter((task) => task.status === 'Concluído').length;
  const today = state.tasks.filter((task) => isToday(task.date)).length;
  const unattended = state.tasks.filter((task) => task.status !== 'Concluído' && !task.analyst).length;
  const overdue = state.tasks.filter(
    (task) => task.status !== 'Concluído' && getTaskAgeInMinutes(task) >= 480
  ).length;

  const cards = [
    {
      label: 'Atendimentos ativos',
      value: active,
      detail: `${total ? Math.round((active / total) * 100) : 0}% do total`
    },
    {
      label: 'Finalizados',
      value: concluded,
      detail: `${concluded} concluídos recentemente`
    },
    {
      label: 'Novos hoje',
      value: today,
      detail: today ? 'Monitorar fluxos de entrada' : 'Sem novos registros hoje'
    },
    {
      label: 'Aguardando analista',
      value: unattended,
      detail: `${overdue} críticos (>8h)`
    }
  ];

  const storageLabel = state.status.googleConfigured ? 'Google Sheets' : 'Armazenamento local';
  const storageDetail = state.status.googleConfigured
    ? 'Sincronização ativa com a planilha'
    : 'Modo local para testes/desenvolvimento';
  cards.push({
    label: 'Integração de dados',
    value: storageLabel,
    detail: storageDetail
  });

  const whatsapp = state.status.whatsapp || {};
  const whatsappLabel = whatsapp.session || 'Não configurada';
  const whatsappDetail = whatsapp.session
    ? whatsapp.active
      ? 'Conectado ao WhatsApp'
      : 'Aguardando pareamento'
    : 'Informe uma sessão para iniciar';
  cards.push({
    label: 'Sessão WhatsApp',
    value: whatsappLabel,
    detail: whatsappDetail
  });

  cards.forEach((card) => {
    const el = document.createElement('article');
    el.className = 'summary-card';
    el.innerHTML = `<span>${card.label}</span><strong>${card.value}</strong><small>${card.detail}</small>`;
    summaryEl.appendChild(el);
  });
}

function updateSettingsSummaryInfo() {
  if (!settingsStorageInfo || !settingsWhatsappInfo) {
    return;
  }
  const storage = state.status.googleConfigured ? 'Google Sheets' : 'Armazenamento local';
  settingsStorageInfo.textContent = storage;
  const whatsapp = state.status.whatsapp || {};
  const whatsappText = whatsapp.session
    ? `${whatsapp.session} · ${whatsapp.active ? 'conectado' : 'aguardando conexão'}`
    : 'Sessão não configurada';
  settingsWhatsappInfo.textContent = whatsappText;
}

function populateSettingsForm() {
  if (!settingsForm) {
    return;
  }
  const form = settingsForm.elements;
  form.whatsappSession.value = state.settings.whatsappSession || '';
  form.analystName.value = state.settings.analystName || '';
  form.googleSheetId.value = state.settings.googleSheetId || '';
  form.googleClientEmail.value = state.settings.googleClientEmail || '';
  form.googlePrivateKey.value = decodePrivateKey(state.settings.googlePrivateKey || '');
  form.googleProjectId.value = state.settings.googleProjectId || '';
}

function setSettingsFeedback(message, status = 'info') {
  if (!settingsFeedbackEl) {
    return;
  }
  if (settingsFeedbackTimeout) {
    clearTimeout(settingsFeedbackTimeout);
  }
  settingsFeedbackEl.textContent = message;
  if (message) {
    settingsFeedbackEl.dataset.status = status;
  } else {
    delete settingsFeedbackEl.dataset.status;
  }
  if (message) {
    settingsFeedbackTimeout = setTimeout(() => {
      settingsFeedbackEl.textContent = '';
      delete settingsFeedbackEl.dataset.status;
    }, 4000);
  }
}

function toggleSettingsDrawer(open) {
  if (!settingsOverlay) {
    return;
  }
  const shouldOpen = Boolean(open);
  settingsOverlay.classList.toggle('is-open', shouldOpen);
  settingsOverlay.setAttribute('aria-hidden', String(!shouldOpen));
  if (shouldOpen) {
    populateSettingsForm();
    settingsForm?.elements.whatsappSession?.focus();
  } else {
    openSettingsButton?.focus();
  }
}

function handleSettingsOverlayClick(event) {
  if (event.target === settingsOverlay) {
    toggleSettingsDrawer(false);
  }
}

async function loadSettings() {
  try {
    const data = await fetchJson('/api/settings');
    state.settings = data.settings ?? state.settings;
    applySystemStatus(data.status ?? {});
    populateSettingsForm();
    renderSummary();
  } catch (error) {
    console.error('Erro ao carregar configurações', error);
    setSettingsFeedback('Não foi possível carregar as configurações.', 'error');
  }
}

async function saveSettings(event) {
  event.preventDefault();
  if (!settingsForm) {
    return;
  }
  const formData = new FormData(settingsForm);
  const payload = {
    whatsappSession: formData.get('whatsappSession')?.toString().trim() || '',
    analystName: formData.get('analystName')?.toString().trim() || '',
    googleSheetId: formData.get('googleSheetId')?.toString().trim() || '',
    googleClientEmail: formData.get('googleClientEmail')?.toString().trim() || '',
    googlePrivateKey: encodePrivateKey(formData.get('googlePrivateKey')?.toString() || ''),
    googleProjectId: formData.get('googleProjectId')?.toString().trim() || ''
  };
  try {
    setSettingsFeedback('Salvando configurações...', 'info');
    const data = await fetchJson('/api/settings', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    state.settings = data.settings ?? state.settings;
    applySystemStatus(data.status ?? {});
    populateSettingsForm();
    renderSummary();
    setSettingsFeedback('Configurações salvas com sucesso.', 'success');
  } catch (error) {
    console.error('Erro ao salvar configurações', error);
    setSettingsFeedback(error.message, 'error');
  }
}

function renderStatusFilters() {
  statusFiltersEl.innerHTML = '';
  const counts = state.tasks.reduce((acc, task) => {
    acc[task.status] = (acc[task.status] || 0) + 1;
    return acc;
  }, {});
  if (state.filters.status !== 'all' && !counts[state.filters.status]) {
    state.filters.status = 'all';
  }
  const statuses = Object.keys(counts).sort();
  const options = [{ value: 'all', label: `Todos (${state.tasks.length})` }];
  statuses.forEach((status) => {
    options.push({ value: status, label: `${status} (${counts[status]})` });
  });
  options.forEach((option) => {
    const button = document.createElement('button');
    button.type = 'button';
    button.textContent = option.label;
    if (state.filters.status === option.value) {
      button.classList.add('is-active');
    }
    button.addEventListener('click', () => {
      state.filters.status = option.value;
      renderFilters();
      renderBoard();
      renderInsights();
    });
    statusFiltersEl.appendChild(button);
  });
}

function renderCategoryFilters() {
  categoryFiltersEl.innerHTML = '';
  const counts = state.tasks.reduce((acc, task) => {
    const key = task.category || 'Sem categoria';
    acc[key] = (acc[key] || 0) + 1;
    return acc;
  }, {});
  const availableCategories = new Set(Object.keys(counts));
  for (const name of Array.from(state.filters.categories)) {
    if (!availableCategories.has(name)) {
      state.filters.categories.delete(name);
    }
  }
  const categories = Object.keys(counts).sort((a, b) => counts[b] - counts[a]);
  categories.forEach((name) => {
    const button = document.createElement('button');
    button.type = 'button';
    button.textContent = `${name} (${counts[name]})`;
    if (state.filters.categories.has(name)) {
      button.classList.add('is-active');
    }
    button.addEventListener('click', () => {
      if (state.filters.categories.has(name)) {
        state.filters.categories.delete(name);
      } else {
        state.filters.categories.add(name);
      }
      renderFilters();
      renderBoard();
      renderInsights();
    });
    categoryFiltersEl.appendChild(button);
  });
}

function renderFilters() {
  renderStatusFilters();
  renderCategoryFilters();
  updateViewButtons();
  showCompletedInput.checked = state.filters.showCompleted;
}

function updateViewButtons() {
  const buttons = viewToggleEl.querySelectorAll('button[data-view]');
  buttons.forEach((button) => {
    if (button.dataset.view === state.viewMode) {
      button.classList.add('is-active');
    } else {
      button.classList.remove('is-active');
    }
  });
}

function renderBoard() {
  boardEl.innerHTML = '';
  const tasks = getFilteredTasks();
  if (!tasks.length) {
    const empty = document.createElement('div');
    empty.className = 'empty-state';
    empty.innerHTML = '<strong>Nenhum atendimento encontrado</strong>Ajuste os filtros ou aguarde novas interações.';
    boardEl.appendChild(empty);
    return;
  }

  if (state.viewMode === 'analyst') {
    renderAnalystBoard(tasks);
  } else {
    renderCategoryBoard(tasks);
  }
}

function renderCategoryBoard(tasks) {
  const definedCategories = state.categories.length
    ? state.categories.map((category) => ({
        name: category.name,
        color: category.color
      }))
    : [];

  const tasksByCategory = tasks.reduce((acc, task) => {
    const key = task.category || 'Sem categoria';
    if (!acc.has(key)) {
      const color = state.colors.get(task.category) || state.colors.get(key);
      acc.set(key, {
        name: key,
        color,
        tasks: []
      });
    }
    acc.get(key).tasks.push(task);
    return acc;
  }, new Map());

  definedCategories.forEach((category) => {
    if (!tasksByCategory.has(category.name)) {
      tasksByCategory.set(category.name, { ...category, tasks: [] });
    } else if (category.color && !tasksByCategory.get(category.name).color) {
      tasksByCategory.get(category.name).color = category.color;
    }
  });

  const merged = Array.from(tasksByCategory.values());
  merged.sort((a, b) => b.tasks.length - a.tasks.length);

  merged.forEach((category) => {
    const column = document.createElement('section');
    column.className = 'column';
    column.style.setProperty('border-top', `6px solid ${category.color || '#2563eb'}`);

    const header = document.createElement('header');
    const title = document.createElement('h2');
    title.textContent = category.name;
    const amount = document.createElement('span');
    const openTasks = category.tasks.filter((task) => task.status !== 'Concluído');
    amount.textContent = `${openTasks.length} em aberto`;

    header.appendChild(title);
    header.appendChild(amount);

    const list = document.createElement('div');
    list.className = 'task-list';

    if (!category.tasks.length) {
      const empty = document.createElement('p');
      empty.className = 'empty-message';
      empty.textContent = 'Nenhum atendimento pendente para esta categoria.';
      list.appendChild(empty);
    } else {
      const sortedTasks = [...category.tasks].sort(
        (a, b) => getTaskAgeInMinutes(b) - getTaskAgeInMinutes(a)
      );
      sortedTasks.forEach((task) => {
        list.appendChild(createTaskCard(task));
      });
    }

    column.appendChild(header);
    column.appendChild(list);
    boardEl.appendChild(column);
  });
}

function renderAnalystBoard(tasks) {
  const analystsMap = new Map();
  state.analysts.forEach((analyst) => {
    analystsMap.set(analyst.name, { ...analyst, tasks: [] });
  });

  tasks.forEach((task) => {
    const key = task.analyst || 'Sem analista definido';
    if (!analystsMap.has(key)) {
      analystsMap.set(key, {
        name: key,
        status: key === 'Sem analista definido' ? 'Atribuir' : 'Indefinido',
        tasks: []
      });
    }
    analystsMap.get(key).tasks.push(task);
  });

  const columns = Array.from(analystsMap.values()).sort((a, b) => {
    const priority = (analyst) => {
      const status = (analyst.status || '').toLowerCase();
      if (status.includes('dispon')) return 0;
      if (status.includes('atendimento') || status.includes('ocup')) return 1;
      if (status.includes('ausente')) return 2;
      return 3;
    };
    const weight = priority(a) - priority(b);
    if (weight !== 0) {
      return weight;
    }
    return (b.tasks?.length || 0) - (a.tasks?.length || 0);
  });

  columns.forEach((analyst) => {
    const column = document.createElement('section');
    column.className = 'column';

    const header = document.createElement('header');
    const title = document.createElement('h2');
    title.textContent = analyst.name;
    const amount = document.createElement('span');
    amount.textContent = `${analyst.tasks.length} atendimentos`;

    header.appendChild(title);
    header.appendChild(amount);

    const list = document.createElement('div');
    list.className = 'task-list';

    if (!analyst.tasks.length) {
      const empty = document.createElement('p');
      empty.className = 'empty-message';
      empty.textContent = 'Sem atendimentos atribuídos.';
      list.appendChild(empty);
    } else {
      const sorted = [...analyst.tasks].sort(
        (a, b) => getTaskAgeInMinutes(b) - getTaskAgeInMinutes(a)
      );
      sorted.forEach((task) => {
        list.appendChild(createTaskCard(task));
      });
    }

    column.appendChild(header);
    column.appendChild(list);
    boardEl.appendChild(column);
  });
}

function createTaskCard(task) {
  const card = taskTemplate.content.firstElementChild.cloneNode(true);
  const numberEl = card.querySelector('.task-number');
  const statusEl = card.querySelector('.task-status');
  const priorityEl = card.querySelector('.task-priority');
  const categoryEl = card.querySelector('.task-category');
  const createdEl = card.querySelector('.task-created');
  const ageEl = card.querySelector('.task-age');
  const messageEl = card.querySelector('.task-message');
  const analystEl = card.querySelector('.task-analyst');
  const reminderEl = card.querySelector('.task-reminder');
  const copyButton = card.querySelector('.task-copy');
  const reminderButton = card.querySelector('.task-remind');
  const completeButton = card.querySelector('.task-complete');

  numberEl.textContent = task.number || `ID ${task.id}`;
  const statusText = task.status || 'Status não informado';
  statusEl.textContent = statusText;
  statusEl.classList.add(getStatusClass(statusText));

  const priority = determinePriority(task);
  priorityEl.textContent = priority.label;

  if (priority.level === 'critical') {
    card.classList.add('task-card--critical');
  } else if (priority.level === 'warning') {
    card.classList.add('task-card--warning');
  } else if (priority.level === 'completed') {
    card.classList.add('task-card--completed');
  }

  const categoryName = task.category || 'Sem categoria';
  categoryEl.textContent = categoryName;
  const categoryColor = state.colors.get(task.category) || state.colors.get(categoryName);
  if (categoryColor) {
    categoryEl.style.backgroundColor = categoryColor;
    categoryEl.style.color = '#fff';
  }

  createdEl.textContent = formatDateTime(task.date);
  const ageMinutes = getTaskAgeInMinutes(task);
  ageEl.textContent =
    task.status === 'Concluído'
      ? `Registrado há ${formatDuration(ageMinutes)}`
      : `Em aberto há ${formatDuration(ageMinutes)}`;
  messageEl.textContent = task.message || 'Sem descrição informada.';

  const analystName = task.analyst?.trim();
  analystEl.textContent = analystName
    ? `Responsável: ${analystName}`
    : 'Sem analista atribuído';

  const reminder = state.reminders.get(task.id);
  if (reminder) {
    reminderEl.classList.add('is-visible');
    reminderEl.textContent = formatReminderTime(reminder.dueAt);
    card.classList.add('task-card--reminder');
  }

  copyButton.addEventListener('click', () => copyTaskNumber(task));
  reminderButton.addEventListener('click', () => scheduleReminder(task));
  completeButton.addEventListener('click', () => concludeTask(task));

  if (task.status === 'Concluído') {
    completeButton.disabled = true;
    completeButton.textContent = 'Atendimento concluído';
    reminderButton.disabled = true;
  }

  return card;
}

function renderInsights() {
  insightsEl.innerHTML = '';
  insightsEl.appendChild(createCategoryInsight());
  insightsEl.appendChild(createAnalystInsight());
  insightsEl.appendChild(createSlaInsight());
  const reminderInsight = createReminderInsight();
  if (reminderInsight) {
    insightsEl.appendChild(reminderInsight);
  }
}

function createInsightCard(title) {
  const card = document.createElement('section');
  card.className = 'insight-card';
  const heading = document.createElement('h3');
  heading.textContent = title;
  card.appendChild(heading);
  return card;
}

function createCategoryInsight() {
  const card = createInsightCard('Categorias em destaque');
  const list = document.createElement('div');
  list.className = 'insight-list';
  const openTasks = state.tasks.filter((task) => task.status !== 'Concluído');
  if (!openTasks.length) {
    const empty = document.createElement('span');
    empty.textContent = 'Nenhum atendimento aberto no momento.';
    list.appendChild(empty);
  } else {
    const counts = openTasks.reduce((acc, task) => {
      const key = task.category || 'Sem categoria';
      acc[key] = (acc[key] || 0) + 1;
      return acc;
    }, {});
    const total = openTasks.length;
    Object.entries(counts)
      .sort(([, a], [, b]) => b - a)
      .slice(0, 5)
      .forEach(([name, value]) => {
        const item = document.createElement('div');
        item.className = 'insight-list__item';
        const label = document.createElement('span');
        label.textContent = name;
        const count = document.createElement('strong');
        count.textContent = value;
        item.appendChild(label);
        item.appendChild(count);
        const progress = document.createElement('div');
        progress.className = 'progress';
        const bar = document.createElement('div');
        bar.className = 'progress__bar';
        bar.style.width = `${Math.round((value / total) * 100)}%`;
        progress.appendChild(bar);
        list.appendChild(item);
        list.appendChild(progress);
      });
  }
  card.appendChild(list);
  return card;
}

function createAnalystInsight() {
  const card = createInsightCard('Status dos analistas');
  const list = document.createElement('div');
  list.className = 'insight-list';
  if (!state.analysts.length) {
    const empty = document.createElement('span');
    empty.textContent = 'Sem informações de analistas disponíveis.';
    list.appendChild(empty);
  } else {
    const tasksByAnalyst = state.tasks.reduce((acc, task) => {
      const key = task.analyst || 'Sem analista definido';
      acc[key] = (acc[key] || 0) + (task.status === 'Concluído' ? 0 : 1);
      return acc;
    }, {});

    state.analysts
      .slice()
      .sort((a, b) => a.name.localeCompare(b.name))
      .forEach((analyst) => {
        const item = document.createElement('div');
        item.className = 'insight-list__item';
        const info = document.createElement('div');
        info.className = 'insight-analyst__info';
        const name = document.createElement('strong');
        name.textContent = analyst.name;
        info.appendChild(name);
        const status = document.createElement('span');
        status.className = 'analyst-status';
        status.dataset.status = analyst.status || 'Indefinido';
        status.textContent = analyst.status || 'Indefinido';
        info.appendChild(status);
        const load = document.createElement('span');
        load.textContent = `${tasksByAnalyst[analyst.name] || 0} atendimentos`;
        item.appendChild(info);
        item.appendChild(load);
        list.appendChild(item);
      });

    const unassigned = tasksByAnalyst['Sem analista definido'];
    if (unassigned) {
      const item = document.createElement('div');
      item.className = 'insight-list__item';
      const label = document.createElement('strong');
      label.textContent = 'Sem analista';
      const value = document.createElement('span');
      value.textContent = `${unassigned} pendentes`;
      item.appendChild(label);
      item.appendChild(value);
      list.appendChild(item);
    }
  }
  card.appendChild(list);
  return card;
}

function createSlaInsight() {
  const card = createInsightCard('Monitor de SLA');
  const list = document.createElement('div');
  list.className = 'insight-list';
  const buckets = {
    ateDuasHoras: 0,
    entreDuasEQuatro: 0,
    entreQuatroEOito: 0,
    acimaOitoHoras: 0
  };
  const openTasks = state.tasks.filter((task) => task.status !== 'Concluído');
  openTasks.forEach((task) => {
    const age = getTaskAgeInMinutes(task);
    if (age <= 120) {
      buckets.ateDuasHoras += 1;
    } else if (age <= 240) {
      buckets.entreDuasEQuatro += 1;
    } else if (age <= 480) {
      buckets.entreQuatroEOito += 1;
    } else {
      buckets.acimaOitoHoras += 1;
    }
  });
  const entries = [
    ['Até 2h', buckets.ateDuasHoras],
    ['2h - 4h', buckets.entreDuasEQuatro],
    ['4h - 8h', buckets.entreQuatroEOito],
    ['> 8h', buckets.acimaOitoHoras]
  ];
  if (!openTasks.length) {
    const empty = document.createElement('span');
    empty.textContent = 'Nenhum atendimento em aberto no momento.';
    list.appendChild(empty);
  } else {
    entries.forEach(([label, value]) => {
      const item = document.createElement('div');
      item.className = 'insight-list__item';
      const labelEl = document.createElement('span');
      labelEl.textContent = label;
      const valueEl = document.createElement('strong');
      valueEl.textContent = value;
      item.appendChild(labelEl);
      item.appendChild(valueEl);
      list.appendChild(item);
    });
  }
  card.appendChild(list);
  return card;
}

function createReminderInsight() {
  if (!state.reminders.size) {
    return null;
  }
  const card = createInsightCard('Lembretes ativos');
  const list = document.createElement('div');
  list.className = 'insight-list';
  Array.from(state.reminders.entries())
    .sort(([, a], [, b]) => a.dueAt - b.dueAt)
    .forEach(([taskId, reminder]) => {
      const task = state.tasks.find((item) => item.id === taskId);
      if (!task) {
        return;
      }
      const item = document.createElement('div');
      item.className = 'insight-list__item';
      const label = document.createElement('span');
      label.textContent = task.number || String(task.id);
      const value = document.createElement('span');
      value.textContent = formatReminderTime(reminder.dueAt);
      item.appendChild(label);
      item.appendChild(value);
      list.appendChild(item);
    });
  if (!list.children.length) {
    const empty = document.createElement('span');
    empty.textContent = 'Nenhum lembrete pendente.';
    list.appendChild(empty);
  }
  card.appendChild(list);
  return card;
}

function copyTaskNumber(task) {
  const value = task.number || String(task.id);
  if (navigator.clipboard?.writeText) {
    navigator.clipboard
      .writeText(value)
      .then(() => {
        alert(`Número ${value} copiado para a área de transferência.`);
      })
      .catch(() => {
        window.prompt('Copie manualmente o número', value);
      });
  } else {
    window.prompt('Copie manualmente o número', value);
  }
}

function scheduleReminder(task) {
  const existingReminder = state.reminders.get(task.id);
  const baseMinutes = existingReminder
    ? Math.round((existingReminder.dueAt - Date.now()) / 60000)
    : 30;
  const defaultMinutes = Number.isFinite(baseMinutes) && baseMinutes > 0 ? baseMinutes : 30;
  const input = window.prompt(
    `Em quantos minutos devemos lembrar sobre o atendimento ${task.number || task.id}?`,
    String(defaultMinutes)
  );
  if (!input) {
    return;
  }
  const minutes = Number.parseInt(input, 10);
  if (!Number.isFinite(minutes) || minutes <= 0) {
    alert('Informe um valor válido em minutos.');
    return;
  }
  if (existingReminder) {
    clearTimeout(existingReminder.timeout);
  }
  const dueAt = Date.now() + minutes * 60000;
  const timeout = setTimeout(() => {
    alert(`Lembrete: revisar atendimento ${task.number || task.id}.`);
    state.reminders.delete(task.id);
    renderBoard();
    renderInsights();
  }, minutes * 60000);
  state.reminders.set(task.id, { dueAt, timeout });
  renderBoard();
  renderInsights();
}

async function concludeTask(task) {
  if (task.status === 'Concluído') {
    return;
  }
  if (!confirm(`Marcar atendimento ${task.id} como concluído?`)) {
    return;
  }
  try {
    await fetchJson(`/api/tasks/${task.id}/complete`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ analyst: task.analyst })
    });
    const reminder = state.reminders.get(task.id);
    if (reminder) {
      clearTimeout(reminder.timeout);
      state.reminders.delete(task.id);
    }
    await loadTasks(true);
  } catch (error) {
    alert(error.message);
  }
}

async function loadCategories() {
  try {
    const data = await fetchJson('/api/keywords');
    state.categories = data.categories ?? [];
    state.categories.forEach((category) => state.colors.set(category.name, category.color));
  } catch (error) {
    console.error('Erro ao carregar categorias', error);
  }
}

async function loadAnalysts() {
  try {
    const data = await fetchJson('/api/analysts');
    state.analysts = data.analysts ?? [];
    if (state.tasks.length) {
      renderInsights();
    }
  } catch (error) {
    console.warn('Não foi possível carregar analistas:', error.message);
  }
}

function removeStaleReminders() {
  const validIds = new Set(state.tasks.filter((task) => task.status !== 'Concluído').map((task) => task.id));
  Array.from(state.reminders.keys()).forEach((taskId) => {
    if (!validIds.has(taskId)) {
      const reminder = state.reminders.get(taskId);
      if (reminder) {
        clearTimeout(reminder.timeout);
      }
      state.reminders.delete(taskId);
    }
  });
}

function applyTasks(tasks, { timestamp } = {}) {
  if (!Array.isArray(tasks)) {
    return;
  }
  state.tasks = tasks;
  removeStaleReminders();
  renderSummary();
  renderFilters();
  renderBoard();
  renderInsights();
  updateLastUpdate(timestamp ?? Date.now());
}

async function loadTasks(refresh = false) {
  const query = refresh ? '?refresh=true' : '';
  const data = await fetchJson(`/api/tasks${query}`);
  applyTasks(data.tasks ?? [], { timestamp: Date.now() });
}

function syncAutoRefresh() {
  clearInterval(autoRefreshHandle);
  if (state.autoRefresh && !isRealtimeConnected()) {
    autoRefreshHandle = setInterval(() => {
      loadTasks(true).catch(() => {});
      loadAnalysts().catch(() => {});
    }, 15000);
  }
}

function scheduleRealtimeReconnect() {
  if (realtimeReconnectTimeout) {
    clearTimeout(realtimeReconnectTimeout);
  }
  realtimeReconnectTimeout = setTimeout(() => {
    realtimeReconnectTimeout = undefined;
    if (!isRealtimeConnected()) {
      connectRealtime();
    }
  }, 5000);
}

function handleRealtimeMessage(event) {
  let message;
  try {
    message = JSON.parse(event.data);
  } catch (error) {
    console.warn('Mensagem WebSocket inválida ignorada:', error);
    return;
  }

  const { type, payload } = message || {};
  switch (type) {
    case 'init':
      if (payload?.tasks) {
        applyTasks(payload.tasks, { timestamp: Date.now() });
      }
      if (payload?.analysts) {
        state.analysts = payload.analysts;
        if (state.viewMode === 'analyst') {
          renderBoard();
        }
        renderInsights();
      }
      if (payload?.settings) {
        state.settings = payload.settings;
        populateSettingsForm();
      }
      if (payload?.status) {
        applySystemStatus(payload.status);
        renderSummary();
      }
      break;
    case 'tasks':
      if (payload?.tasks) {
        applyTasks(payload.tasks, { timestamp: Date.now() });
      }
      break;
    case 'analysts':
      if (payload?.analysts) {
        state.analysts = payload.analysts;
        if (state.viewMode === 'analyst') {
          renderBoard();
        }
        renderInsights();
      }
      break;
    case 'settings':
      if (payload) {
        state.settings = { ...state.settings, ...payload };
        populateSettingsForm();
        renderSummary();
      }
      break;
    case 'status':
      if (payload) {
        applySystemStatus(payload);
        renderSummary();
      }
      break;
    default:
      break;
  }
}

function connectRealtime() {
  if (isRealtimeConnected() || isRealtimeConnecting()) {
    return;
  }

  try {
    const protocol = window.location.protocol === 'https:' ? 'wss' : 'ws';
    const socket = new WebSocket(`${protocol}://${window.location.host}/ws`);
    realtimeSocket = socket;

    socket.addEventListener('open', () => {
      syncAutoRefresh();
    });

    socket.addEventListener('message', handleRealtimeMessage);

    socket.addEventListener('close', () => {
      if (realtimeSocket === socket) {
        realtimeSocket = undefined;
      }
      syncAutoRefresh();
      scheduleRealtimeReconnect();
    });

    socket.addEventListener('error', () => {
      socket.close();
    });
  } catch (error) {
    console.warn('Não foi possível conectar ao canal em tempo real:', error);
    scheduleRealtimeReconnect();
  }
}

function bindEvents() {
  refreshButton.addEventListener('click', () => loadTasks(true));
  searchInput.addEventListener('input', (event) => {
    state.filters.search = event.target.value;
    renderBoard();
    renderInsights();
  });
  showCompletedInput.addEventListener('change', (event) => {
    state.filters.showCompleted = event.target.checked;
    renderBoard();
    renderInsights();
  });
  viewToggleEl.addEventListener('click', (event) => {
    const button = event.target.closest('button[data-view]');
    if (!button) {
      return;
    }
    state.viewMode = button.dataset.view;
    updateViewButtons();
    renderBoard();
  });
  autoRefreshInput.addEventListener('change', (event) => {
    state.autoRefresh = event.target.checked;
    syncAutoRefresh();
  });
  openSettingsButton?.addEventListener('click', () => toggleSettingsDrawer(true));
  closeSettingsButton?.addEventListener('click', () => toggleSettingsDrawer(false));
  settingsOverlay?.addEventListener('click', handleSettingsOverlayClick);
  settingsForm?.addEventListener('submit', saveSettings);
  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape' && settingsOverlay?.classList.contains('is-open')) {
      toggleSettingsDrawer(false);
    }
  });
}

async function bootstrap() {
  bindEvents();
  await loadSettings();
  await Promise.all([loadCategories(), loadAnalysts()]);
  await loadTasks(true);
  connectRealtime();
  syncAutoRefresh();
}

bootstrap().catch((error) => {
  console.error('Erro ao iniciar painel', error);
});
