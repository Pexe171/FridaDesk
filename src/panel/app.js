function createDefaultStatus() {
  const now = Date.now();
  return {
    storage: 'local',
    googleConfigured: false,
    analystName: '',
    whatsapp: {
      active: false,
      session: '',
      connected: false,
      initializing: false,
      qr: null,
      qrImage: null,
      qrGeneratedAt: null,
      readyAt: null,
      messageCount: 0,
      lastMessageAt: null,
      error: null
    },
    websocket: {
      clients: 0,
      stations: []
    },
    health: {
      status: 'ok',
      startedAt: now,
      lastUpdated: now
    }
  };
}

const state = {
  categories: [],
  tasks: [],
  analysts: [],
  colors: new Map(),
  filters: {
    status: 'all',
    search: '',
    categories: new Set(),
    showCompleted: false,
    privateOnly: true
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
  status: createDefaultStatus()
};

let autoRefreshHandle;
let settingsFeedbackTimeout;
let realtimeSocket;
let realtimeReconnectTimeout;
let resetWhatsappFeedbackTimeout;
let lastIdentifySignature = '';
let navigationFeedbackTimeout;
let navigationFeedbackHideTimeout;

const topbarEl = document.querySelector('.topbar');
const summaryEl = document.getElementById('summary');
const boardEl = document.getElementById('board');
const insightsEl = document.getElementById('insights');
const refreshButton = document.getElementById('refreshTasks');
const lastUpdateEl = document.getElementById('lastUpdate');
const whatsappStateEl = document.getElementById('whatsappConnectionState');
const whatsappMessageStatsEl = document.getElementById('whatsappMessageStats');
const whatsappLastMessageEl = document.getElementById('whatsappLastMessage');
const whatsappQrImageEl = document.getElementById('whatsappQrImage');
const whatsappQrPlaceholderEl = document.getElementById('whatsappQrPlaceholder');
const whatsappQrUpdatedEl = document.getElementById('whatsappQrUpdatedAt');
const resetWhatsappButton = document.getElementById('resetWhatsappSession');
const resetWhatsappFeedbackEl = document.getElementById('resetWhatsappFeedback');
const runtimeStorageSummaryEl = document.getElementById('runtimeStorageSummary');
const runtimeHealthStatusEl = document.getElementById('runtimeHealthStatus');
const runtimeStationsListEl = document.getElementById('runtimeStationsList');
const runtimeStationsCountEl = document.getElementById('runtimeStationsCount');
const taskTemplate = document.getElementById('task-card');
const searchInput = document.getElementById('searchTasks');
const statusFiltersEl = document.getElementById('statusFilters');
const categoryFiltersEl = document.getElementById('categoryFilters');
const viewToggleEl = document.getElementById('viewToggle');
const showCompletedInput = document.getElementById('showCompleted');
const filterPrivateInput = document.getElementById('filterPrivate');
const autoRefreshInput = document.getElementById('autoRefresh');
const openSettingsButton = document.getElementById('openSettings');
const settingsOverlay = document.getElementById('settingsOverlay');
const closeSettingsButton = document.getElementById('closeSettings');
const settingsForm = document.getElementById('settingsForm');
const settingsFeedbackEl = document.getElementById('settingsFeedback');
const settingsStorageInfo = document.getElementById('settingsStorageInfo');
const settingsWhatsappInfo = document.getElementById('settingsWhatsappInfo');
const resetFiltersButton = document.getElementById('resetFilters');
const navigationFeedbackEl = document.getElementById('navigationFeedback');
const navigationButtons = Array.from(
  document.querySelectorAll('.sidebar__link[data-action]')
);
const navigationToneClasses = ['app-toast--info', 'app-toast--warning'];

function isGroupIdentifier(value) {
  if (!value) {
    return false;
  }
  const normalized = value.toString().toLowerCase();
  if (normalized.includes('@g.us')) {
    return true;
  }
  if (normalized.includes('@broadcast')) {
    return true;
  }
  if (normalized.includes('-') && !/^[+]?\d+$/.test(normalized.replace(/@.+$/, ''))) {
    return true;
  }
  return false;
}

function formatContactNumber(value) {
  if (!value) {
    return { display: 'Contato não identificado', copy: '', isGroup: false };
  }
  let normalized = value.toString().trim();
  const isGroup = isGroupIdentifier(normalized);
  if (normalized.includes('@')) {
    normalized = normalized.replace(/@.+$/, '');
  }
  const digitsOnly = normalized.replace(/\D/g, '');
  const copy = digitsOnly || normalized;
  let display = normalized;
  if (!display) {
    display = isGroup ? 'Grupo do WhatsApp' : 'Contato não identificado';
  }
  if (!isGroup && digitsOnly.length >= 10) {
    const national = digitsOnly.slice(-11);
    const country = digitsOnly.length > national.length ? digitsOnly.slice(0, digitsOnly.length - national.length) : '55';
    const area = national.slice(0, 2) || '00';
    const subscriber = national.slice(2);
    const leading = subscriber.slice(0, Math.max(subscriber.length - 4, 0)) || subscriber;
    const trailing = subscriber.length > 4 ? subscriber.slice(-4) : '';
    display = trailing
      ? `+${country} (${area}) ${leading}-${trailing}`
      : `+${country} (${area}) ${leading}`;
  } else if (isGroup) {
    display = `Grupo ${normalized}`;
  }
  return { display, copy, isGroup };
}

function getTasksUniverse() {
  if (state.filters.privateOnly) {
    return state.tasks.filter((task) => !task.isGroup);
  }
  return state.tasks.slice();
}

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
  const defaults = createDefaultStatus();
  const whatsapp = {
    ...defaults.whatsapp,
    ...(status.whatsapp || {})
  };
  const websocket = {
    clients: status.websocket?.clients ?? defaults.websocket.clients,
    stations: Array.isArray(status.websocket?.stations)
      ? status.websocket.stations
      : defaults.websocket.stations
  };
  const health = {
    ...defaults.health,
    ...(status.health || {})
  };
  state.status = {
    ...defaults,
    ...status,
    storage: status.storage || defaults.storage,
    googleConfigured: Boolean(status.googleConfigured),
    analystName: status.analystName || state.settings.analystName || defaults.analystName,
    whatsapp,
    websocket,
    health
  };
  updateSettingsSummaryInfo();
  renderRuntimeStatus();
  identifyRealtimeStation();
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

function parseTaskTimestamp(raw) {
  if (!raw) {
    return null;
  }
  if (raw instanceof Date) {
    return raw;
  }
  if (typeof raw === 'number') {
    const fromNumber = new Date(raw);
    return Number.isNaN(fromNumber.getTime()) ? null : fromNumber;
  }
  if (typeof raw === 'string') {
    const parsed = new Date(raw);
    if (!Number.isNaN(parsed.getTime())) {
      return parsed;
    }
    return parseTaskDate(raw);
  }
  return null;
}

function getTaskAgeInMinutes(task) {
  const createdAt = parseTaskDate(task.date);
  if (!createdAt) {
    return 0;
  }
  const diff = Date.now() - createdAt.getTime();
  return Math.max(0, Math.floor(diff / 60000));
}

function getTaskResolutionMinutes(task) {
  if (!task) {
    return null;
  }
  const rawResolution = task.resolutionMinutes ?? task.resolutionTime ?? task.durationMinutes;
  if (Number.isFinite(rawResolution)) {
    return Math.max(0, Math.round(rawResolution));
  }
  const completedAt =
    parseTaskTimestamp(task.completedAt ?? task.closedAt ?? task.finishedAt ?? task.resolvedAt) ?? null;
  const createdAt = parseTaskTimestamp(task.date);
  if (completedAt && createdAt) {
    const diff = completedAt.getTime() - createdAt.getTime();
    return diff > 0 ? Math.floor(diff / 60000) : 0;
  }
  if (task.status === 'Concluído' && createdAt) {
    const diff = Date.now() - createdAt.getTime();
    return diff > 0 ? Math.floor(diff / 60000) : 0;
  }
  return null;
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

function formatTimestamp(timestamp) {
  if (!timestamp) {
    return 'Nunca';
  }
  const date = new Date(Number(timestamp));
  if (Number.isNaN(date.getTime())) {
    return 'Nunca';
  }
  return date.toLocaleString('pt-BR', {
    hour12: false
  });
}

function formatRelativeTimestamp(timestamp) {
  if (!timestamp) {
    return 'Nunca';
  }
  const diff = Date.now() - Number(timestamp);
  if (Number.isNaN(diff) || diff < 0) {
    return 'Agora';
  }
  const minutes = Math.floor(diff / 60000);
  if (minutes < 1) {
    return 'Agora';
  }
  if (minutes < 60) {
    return `${minutes} min atrás`;
  }
  const hours = Math.floor(minutes / 60);
  if (hours < 24) {
    const remainingMinutes = minutes % 60;
    if (remainingMinutes === 0) {
      return `${hours}h atrás`;
    }
    return `${hours}h ${remainingMinutes}min atrás`;
  }
  const days = Math.floor(hours / 24);
  const remainingHours = hours % 24;
  if (remainingHours === 0) {
    return `${days}d atrás`;
  }
  return `${days}d ${remainingHours}h atrás`;
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
  const { status, search, categories, showCompleted, privateOnly } = state.filters;
  const searchTerm = search.trim().toLowerCase();
  return state.tasks.filter((task) => {
    if (privateOnly && task.isGroup) {
      return false;
    }
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
    const haystack = [
      task.displayNumber,
      task.copyNumber,
      task.number,
      task.message,
      task.category,
      task.analyst,
      task.status
    ]
      .filter(Boolean)
      .join(' ')
      .toLowerCase();
    return haystack.includes(searchTerm);
  });
}

function renderSummary() {
  summaryEl.innerHTML = '';
  const baseTasks = getTasksUniverse();
  const total = baseTasks.length;
  const active = baseTasks.filter((task) => task.status !== 'Concluído').length;
  const concluded = baseTasks.filter((task) => task.status === 'Concluído').length;
  const today = baseTasks.filter((task) => isToday(task.date)).length;
  const unattended = baseTasks.filter((task) => task.status !== 'Concluído' && !task.analyst).length;
  const overdue = baseTasks.filter(
    (task) => task.status !== 'Concluído' && getTaskAgeInMinutes(task) >= 480
  ).length;
  const privateConversations = state.tasks.filter((task) => !task.isGroup).length;
  const groupConversations = state.tasks.filter((task) => task.isGroup).length;
  const privateRatio = state.tasks.length
    ? Math.round((privateConversations / state.tasks.length) * 100)
    : 0;
  const groupRatio = state.tasks.length ? Math.round((groupConversations / state.tasks.length) * 100) : 0;

  const storageLabel = state.status.googleConfigured ? 'Google Sheets' : 'Armazenamento local';
  const storageDetail = state.status.googleConfigured
    ? 'Sincronização ativa com a planilha'
    : 'Modo local para testes/desenvolvimento';

  const whatsapp = state.status.whatsapp || {};
  const whatsappLabel = whatsapp.session || 'Não configurada';
  let whatsappDetail;
  if (!whatsapp.session) {
    whatsappDetail = 'Informe uma sessão para iniciar';
  } else if (whatsapp.connected) {
    const messages = whatsapp.messageCount || 0;
    const last = whatsapp.lastMessageAt ? formatRelativeTimestamp(whatsapp.lastMessageAt) : 'sem mensagens';
    whatsappDetail = `Conectado • ${messages} mensagens (${last})`;
  } else if (whatsapp.qrImage) {
    whatsappDetail = 'QR Code disponível para pareamento';
  } else if (whatsapp.initializing) {
    whatsappDetail = 'Inicializando cliente do WhatsApp';
  } else if (whatsapp.error?.message) {
    whatsappDetail = `Erro: ${whatsapp.error.message}`;
  } else if (whatsapp.active) {
    whatsappDetail = 'Tentando reconectar ao WhatsApp';
  } else {
    whatsappDetail = 'Sessão inativa no momento';
  }

  const cards = [
    {
      type: 'active',
      icon: '📞',
      label: 'Atendimentos ativos',
      value: active,
      detail: `${total ? Math.round((active / total) * 100) : 0}% do total`,
      badge: total ? `${total} no painel` : 'Sem fila'
    },
    {
      type: 'done',
      icon: '✅',
      label: 'Finalizados',
      value: concluded,
      detail: concluded ? 'Últimas 24h em alta' : 'Sem fechamentos recentes'
    },
    {
      type: 'new',
      icon: '🆕',
      label: 'Novos hoje',
      value: today,
      detail: today ? 'Acompanhe a entrada de leads' : 'Sem novos registros hoje'
    },
    {
      type: 'alert',
      icon: '⏱️',
      label: 'Aguardando analista',
      value: unattended,
      detail: `${overdue} críticos (>8h)`
    },
    {
      type: 'private',
      icon: '🔒',
      label: 'Conversas privadas',
      value: privateConversations,
      detail: `${privateRatio}% do volume total`,
      badge: groupConversations ? `${groupConversations} grupos (${groupRatio}%)` : 'Sem grupos'
    },
    {
      type: 'integration',
      icon: '🔗',
      label: 'Integração de dados',
      value: storageLabel,
      detail: storageDetail,
      valueType: 'text'
    },
    {
      type: 'whatsapp',
      icon: '⚡',
      label: 'Sessão WhatsApp',
      value: whatsappLabel,
      detail: whatsappDetail,
      valueType: 'text'
    }
  ];

  cards.forEach((card) => {
    const el = document.createElement('article');
    el.className = 'summary-card';
    if (card.type) {
      el.dataset.type = card.type;
    }
    const icon = document.createElement('span');
    icon.className = 'summary-card__icon';
    icon.textContent = card.icon || 'ℹ️';

    const body = document.createElement('div');
    body.className = 'summary-card__body';

    const top = document.createElement('div');
    top.className = 'summary-card__top';
    const label = document.createElement('span');
    label.className = 'summary-card__label';
    label.textContent = card.label;
    top.appendChild(label);
    if (card.badge) {
      const badge = document.createElement('span');
      badge.className = 'summary-card__badge';
      badge.textContent = card.badge;
      top.appendChild(badge);
    }

    const value = document.createElement('strong');
    value.className = 'summary-card__value';
    if (card.valueType === 'text') {
      value.classList.add('is-text');
      value.textContent = card.value;
    } else if (typeof card.value === 'number' && Number.isFinite(card.value)) {
      value.textContent = card.value.toLocaleString('pt-BR');
    } else {
      value.textContent = String(card.value ?? '--');
    }

    const detail = document.createElement('small');
    detail.className = 'summary-card__detail';
    detail.textContent = card.detail;

    body.appendChild(top);
    body.appendChild(value);
    body.appendChild(detail);

    el.appendChild(icon);
    el.appendChild(body);
    summaryEl.appendChild(el);
  });
}

function renderRuntimeStatus() {
  const whatsapp = state.status.whatsapp || {};
  const websocket = state.status.websocket || {};
  const health = state.status.health || {};

  if (whatsappStateEl) {
    let statusText = 'Sessão não configurada';
    let statusType = 'offline';
    if (!whatsapp.session) {
      statusText = 'Sessão não configurada';
      statusType = 'offline';
    } else if (whatsapp.connected) {
      statusText = 'Conectado ao WhatsApp';
      statusType = 'online';
    } else if (whatsapp.initializing) {
      statusText = 'Inicializando cliente do WhatsApp...';
      statusType = 'pending';
    } else if (whatsapp.qrImage) {
      statusText = 'QR Code aguardando pareamento';
      statusType = 'pending';
    } else if (whatsapp.error?.message) {
      statusText = `Erro: ${whatsapp.error.message}`;
      statusType = 'error';
    } else if (whatsapp.active) {
      statusText = 'Tentando reconectar ao WhatsApp';
      statusType = 'pending';
    } else {
      statusText = 'Sessão inativa';
      statusType = 'offline';
    }
    whatsappStateEl.textContent = statusText;
    whatsappStateEl.dataset.status = statusType;
  }

  if (whatsappMessageStatsEl) {
    if (!whatsapp.session) {
      whatsappMessageStatsEl.textContent = 'Mensagens registradas: --';
    } else {
      whatsappMessageStatsEl.textContent = `Mensagens registradas: ${whatsapp.messageCount || 0}`;
    }
  }

  if (whatsappLastMessageEl) {
    if (whatsapp.lastMessageAt) {
      whatsappLastMessageEl.textContent = `Última mensagem: ${formatRelativeTimestamp(
        whatsapp.lastMessageAt
      )} (${formatTimestamp(whatsapp.lastMessageAt)})`;
    } else if (whatsapp.session) {
      whatsappLastMessageEl.textContent = 'Última mensagem: nenhuma registrada ainda';
    } else {
      whatsappLastMessageEl.textContent = 'Última mensagem: --';
    }
  }

  if (whatsappQrImageEl && whatsappQrPlaceholderEl) {
    if (whatsapp.qrImage) {
      whatsappQrImageEl.src = whatsapp.qrImage;
      whatsappQrImageEl.alt = 'QR Code do WhatsApp';
      whatsappQrImageEl.removeAttribute('hidden');
      whatsappQrPlaceholderEl.setAttribute('hidden', 'hidden');
      if (whatsappQrUpdatedEl) {
        whatsappQrUpdatedEl.textContent = `Gerado ${formatRelativeTimestamp(
          whatsapp.qrGeneratedAt
        )}`;
        whatsappQrUpdatedEl.removeAttribute('hidden');
      }
    } else {
      whatsappQrImageEl.removeAttribute('src');
      whatsappQrImageEl.setAttribute('hidden', 'hidden');
      let placeholderText = 'Configure uma sessão para gerar o QR Code.';
      if (whatsapp.session) {
        placeholderText = whatsapp.connected
          ? 'Conexão ativa. QR Code não necessário.'
          : 'O QR Code aparecerá aqui quando o WhatsApp solicitar um novo pareamento.';
      }
      whatsappQrPlaceholderEl.textContent = placeholderText;
      whatsappQrPlaceholderEl.removeAttribute('hidden');
      if (whatsappQrUpdatedEl) {
        whatsappQrUpdatedEl.textContent = '';
        whatsappQrUpdatedEl.setAttribute('hidden', 'hidden');
      }
    }
  }

  if (resetWhatsappButton) {
    resetWhatsappButton.disabled = !whatsapp.session || Boolean(resetWhatsappButton.dataset.loading);
  }

  if (runtimeStorageSummaryEl) {
    runtimeStorageSummaryEl.textContent = state.status.googleConfigured
      ? 'Integração com Google Sheets ativa'
      : 'Armazenamento local habilitado';
  }

  if (runtimeHealthStatusEl) {
    const statusLabel = (health.status || 'ok') === 'ok' ? 'Operacional' : health.status;
    const uptimeMs = Math.max(0, Date.now() - (health.startedAt || Date.now()));
    const uptimeMinutes = Math.floor(uptimeMs / 60000);
    const uptimeText = uptimeMinutes ? formatDuration(uptimeMinutes) : 'menos de 1min';
    const lastUpdated = formatRelativeTimestamp(health.lastUpdated);
    runtimeHealthStatusEl.textContent = `Status geral: ${statusLabel} • Uptime ${uptimeText} • Atualizado ${lastUpdated}`;
  }

  if (runtimeStationsCountEl) {
    runtimeStationsCountEl.textContent = websocket.clients ?? 0;
  }

  if (runtimeStationsListEl) {
    runtimeStationsListEl.innerHTML = '';
    const stations = Array.isArray(websocket.stations) ? websocket.stations.slice() : [];
    stations.sort((a, b) => (b.lastSeenAt || 0) - (a.lastSeenAt || 0));
    if (!stations.length) {
      const empty = document.createElement('li');
      empty.className = 'runtime-empty';
      empty.textContent = 'Nenhuma estação conectada no momento.';
      runtimeStationsListEl.appendChild(empty);
    } else {
      stations.forEach((station) => {
        const item = document.createElement('li');
        item.className = 'runtime-station';
        const title = document.createElement('strong');
        title.textContent = station.name || station.session || 'Estação sem identificação';
        item.appendChild(title);
        const details = [];
        if (station.analystName) {
          details.push(`Analista: ${station.analystName}`);
        }
        if (station.session) {
          details.push(`Sessão: ${station.session}`);
        }
        if (station.hostname) {
          details.push(station.hostname);
        }
        const meta = document.createElement('span');
        meta.textContent = details.join(' • ') || 'Sem detalhes adicionais';
        item.appendChild(meta);
        const lastSeen = document.createElement('small');
        const reference = station.lastSeenAt || station.connectedAt;
        lastSeen.textContent = `Ativo ${formatRelativeTimestamp(reference)}`;
        item.appendChild(lastSeen);
        runtimeStationsListEl.appendChild(item);
      });
    }
  }
}

function identifyRealtimeStation(force = false) {
  if (!isRealtimeConnected()) {
    return;
  }
  const payload = {
    station: state.settings.whatsappSession || 'Estação sem sessão',
    analystName: state.settings.analystName || '',
    session: state.settings.whatsappSession || '',
    hostname: window.location.hostname,
    connected: Boolean(state.status.whatsapp?.connected),
    active: Boolean(state.status.whatsapp?.active)
  };
  const signature = JSON.stringify(payload);
  if (!force && signature === lastIdentifySignature) {
    return;
  }
  lastIdentifySignature = signature;
  try {
    realtimeSocket?.send?.(JSON.stringify({ type: 'identify', payload }));
  } catch (error) {
    console.warn('Não foi possível enviar identificação em tempo real:', error);
  }
}

function updateSettingsSummaryInfo() {
  if (!settingsStorageInfo || !settingsWhatsappInfo) {
    return;
  }
  const storage = state.status.googleConfigured ? 'Google Sheets' : 'Armazenamento local';
  settingsStorageInfo.textContent = storage;
  const whatsapp = state.status.whatsapp || {};
  const whatsappText = whatsapp.session
    ? `${whatsapp.session} · ${whatsapp.connected ? 'conectado' : whatsapp.qrImage ? 'aguardando pareamento' : 'aguardando conexão'}`
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

function setResetFeedback(message, status = 'info') {
  if (!resetWhatsappFeedbackEl) {
    return;
  }
  if (resetWhatsappFeedbackTimeout) {
    clearTimeout(resetWhatsappFeedbackTimeout);
  }
  resetWhatsappFeedbackEl.textContent = message;
  if (message) {
    resetWhatsappFeedbackEl.dataset.status = status;
  } else {
    delete resetWhatsappFeedbackEl.dataset.status;
  }
  if (message) {
    resetWhatsappFeedbackTimeout = setTimeout(() => {
      resetWhatsappFeedbackEl.textContent = '';
      delete resetWhatsappFeedbackEl.dataset.status;
    }, 5000);
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

async function handleResetWhatsappSession() {
  if (!resetWhatsappButton) {
    return;
  }
  if (!state.status.whatsapp.session) {
    setResetFeedback('Configure uma sessão do WhatsApp antes de gerar um novo QR Code.', 'warning');
    return;
  }
  try {
    resetWhatsappButton.dataset.loading = 'true';
    resetWhatsappButton.disabled = true;
    setResetFeedback('Solicitando novo QR Code...', 'info');
    const data = await fetchJson('/api/whatsapp/reset-session', { method: 'POST' });
    if (data?.status) {
      applySystemStatus(data.status);
      renderSummary();
    }
    setResetFeedback('Novo QR Code disponível. Escaneie para reconectar.', 'success');
    identifyRealtimeStation(true);
  } catch (error) {
    console.error('Erro ao reiniciar sessão do WhatsApp', error);
    setResetFeedback(error.message || 'Não foi possível reiniciar a sessão.', 'error');
  } finally {
    delete resetWhatsappButton.dataset.loading;
    resetWhatsappButton.disabled = !state.status.whatsapp.session;
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
  const tasks = getTasksUniverse();
  const counts = tasks.reduce((acc, task) => {
    acc[task.status] = (acc[task.status] || 0) + 1;
    return acc;
  }, {});
  if (state.filters.status !== 'all' && !counts[state.filters.status]) {
    state.filters.status = 'all';
  }
  const statuses = Object.keys(counts).sort();
  const options = [{ value: 'all', label: `Todos (${tasks.length})` }];
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
  const tasks = getTasksUniverse();
  const counts = tasks.reduce((acc, task) => {
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
  if (filterPrivateInput) {
    filterPrivateInput.checked = state.filters.privateOnly;
  }
}

function resetFilters() {
  state.filters.status = 'all';
  state.filters.categories = new Set();
  state.filters.search = '';
  state.filters.showCompleted = false;
  state.filters.privateOnly = true;
  if (searchInput) {
    searchInput.value = '';
  }
  if (showCompletedInput) {
    showCompletedInput.checked = false;
  }
  if (filterPrivateInput) {
    filterPrivateInput.checked = true;
  }
  renderSummary();
  renderFilters();
  renderBoard();
  renderInsights();
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

  numberEl.textContent = task.displayNumber || task.number || `ID ${task.id}`;
  if (task.isGroup) {
    numberEl.classList.add('task-number--group');
    card.dataset.origin = 'group';
  } else {
    card.dataset.origin = 'direct';
  }
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

  if (task.isGroup) {
    copyButton.disabled = true;
    copyButton.textContent = 'Grupo';
    copyButton.title = 'Números de grupos não são copiados automaticamente.';
  } else {
    copyButton.addEventListener('click', () => copyTaskNumber(task));
  }
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
  const tasks = getTasksUniverse();
  insightsEl.innerHTML = '';
  insightsEl.appendChild(createCategoryInsight(tasks));
  insightsEl.appendChild(createAnalystInsight(tasks));
  insightsEl.appendChild(createAnalystProductivityInsight(tasks));
  insightsEl.appendChild(createSlaInsight(tasks));
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

function createCategoryInsight(tasks) {
  const card = createInsightCard('Categorias em destaque');
  const list = document.createElement('div');
  list.className = 'insight-list';
  const openTasks = tasks.filter((task) => task.status !== 'Concluído');
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

function createAnalystInsight(tasks) {
  const card = createInsightCard('Status dos analistas');
  const list = document.createElement('div');
  list.className = 'insight-list';
  if (!state.analysts.length) {
    const empty = document.createElement('span');
    empty.textContent = 'Sem informações de analistas disponíveis.';
    list.appendChild(empty);
  } else {
    const tasksByAnalyst = tasks.reduce((acc, task) => {
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

function createAnalystProductivityInsight(tasks) {
  const card = createInsightCard('Estatísticas de Produtividade do Analista');
  const productivityByAnalyst = new Map();

  function ensureAnalystEntry(name) {
    const trimmed = name?.trim();
    if (!trimmed) {
      return null;
    }
    if (!productivityByAnalyst.has(trimmed)) {
      productivityByAnalyst.set(trimmed, {
        name: trimmed,
        status: '',
        open: 0,
        resolved: 0,
        total: 0,
        resolutionSamples: []
      });
    }
    return productivityByAnalyst.get(trimmed);
  }

  state.analysts.forEach((analyst) => {
    const entry = ensureAnalystEntry(analyst.name);
    if (entry) {
      entry.status = analyst.status || entry.status || '';
    }
  });

  tasks.forEach((task) => {
    const entry = ensureAnalystEntry(task.analyst);
    if (!entry) {
      return;
    }
    entry.total += 1;
    if (task.status === 'Concluído') {
      entry.resolved += 1;
      const resolutionMinutes = getTaskResolutionMinutes(task);
      if (Number.isFinite(resolutionMinutes)) {
        entry.resolutionSamples.push(resolutionMinutes);
      }
    } else {
      entry.open += 1;
    }
  });

  const dataset = Array.from(productivityByAnalyst.values()).map((entry) => {
    const averageMinutes = entry.resolutionSamples.length
      ? Math.round(
          entry.resolutionSamples.reduce((total, value) => total + value, 0) /
            entry.resolutionSamples.length
        )
      : null;
    return {
      ...entry,
      averageMinutes
    };
  });

  if (!dataset.length) {
    const empty = document.createElement('span');
    empty.className = 'insight-empty';
    empty.textContent = 'Sem dados de produtividade disponíveis.';
    card.appendChild(empty);
    return card;
  }

  dataset.sort((a, b) => {
    if (b.open !== a.open) {
      return b.open - a.open;
    }
    const aAverage = Number.isFinite(a.averageMinutes) ? a.averageMinutes : Number.POSITIVE_INFINITY;
    const bAverage = Number.isFinite(b.averageMinutes) ? b.averageMinutes : Number.POSITIVE_INFINITY;
    if (aAverage !== bAverage) {
      return aAverage - bAverage;
    }
    return a.name.localeCompare(b.name);
  });

  const table = document.createElement('table');
  table.className = 'insight-table';

  const head = document.createElement('thead');
  const headRow = document.createElement('tr');
  ['Analista', 'Tempo Médio de Resolução', 'Carga de Atendimentos'].forEach((label) => {
    const th = document.createElement('th');
    th.scope = 'col';
    th.textContent = label;
    headRow.appendChild(th);
  });
  head.appendChild(headRow);
  table.appendChild(head);

  const body = document.createElement('tbody');

  const getWorkloadLevel = (open) => {
    if (open >= 10) {
      return 'critical';
    }
    if (open >= 6) {
      return 'high';
    }
    if (open >= 3) {
      return 'attention';
    }
    if (open > 0) {
      return 'normal';
    }
    return 'idle';
  };

  dataset.forEach((entry) => {
    const row = document.createElement('tr');

    const analystCell = document.createElement('td');
    const analystInfo = document.createElement('div');
    analystInfo.className = 'insight-table__analyst';
    const name = document.createElement('strong');
    name.className = 'insight-table__name';
    name.textContent = entry.name;
    analystInfo.appendChild(name);
    if (entry.status) {
      const badge = document.createElement('span');
      badge.className = 'insight-table__status';
      badge.dataset.state = entry.status;
      badge.textContent = entry.status;
      analystInfo.appendChild(badge);
    }
    analystCell.appendChild(analystInfo);
    row.appendChild(analystCell);

    const averageCell = document.createElement('td');
    averageCell.className = 'insight-table__metric';
    const averageValue = document.createElement('span');
    averageValue.className = 'insight-table__metric-value';
    averageValue.textContent = entry.averageMinutes
      ? formatDuration(entry.averageMinutes)
      : 'Sem histórico';
    averageCell.appendChild(averageValue);
    if (entry.resolved) {
      const averageDetail = document.createElement('span');
      averageDetail.className = 'insight-table__metric-detail';
      averageDetail.textContent = `${entry.resolved} concluído${entry.resolved > 1 ? 's' : ''}`;
      averageCell.appendChild(averageDetail);
    }
    row.appendChild(averageCell);

    const workloadCell = document.createElement('td');
    workloadCell.className = 'insight-table__metric';
    const badge = document.createElement('span');
    badge.className = 'insight-table__load-badge';
    badge.dataset.level = getWorkloadLevel(entry.open);
    badge.textContent = `${entry.open}`;
    workloadCell.appendChild(badge);
    const detail = document.createElement('span');
    detail.className = 'insight-table__load-detail';
    detail.textContent = entry.total
      ? `${entry.open} em aberto · ${entry.total} no total`
      : entry.open
        ? 'Atendimentos em aberto'
        : 'Sem atendimentos';
    workloadCell.appendChild(detail);
    row.appendChild(workloadCell);

    body.appendChild(row);
  });

  table.appendChild(body);
  card.appendChild(table);
  return card;
}

function createSlaInsight(tasks) {
  const card = createInsightCard('Monitor de SLA');
  const list = document.createElement('div');
  list.className = 'insight-list';
  const buckets = {
    ateDuasHoras: 0,
    entreDuasEQuatro: 0,
    entreQuatroEOito: 0,
    acimaOitoHoras: 0
  };
  const openTasks = tasks.filter((task) => task.status !== 'Concluído');
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
      label.textContent = task.displayNumber || task.number || String(task.id);
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
  const value = task.copyNumber || task.number || String(task.id);
  if (!value) {
    alert('Número do contato indisponível para cópia.');
    return;
  }
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
  const label = task.displayNumber || task.number || task.id;
  const input = window.prompt(
    `Em quantos minutos devemos lembrar sobre o atendimento ${label}?`,
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
    const reminderLabel = task.displayNumber || task.number || task.id;
    alert(`Lembrete: revisar atendimento ${reminderLabel}.`);
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
  state.tasks = tasks.map((task) => {
    const formatted = formatContactNumber(task.number);
    return {
      ...task,
      displayNumber: formatted.display,
      copyNumber: formatted.copy,
      isGroup: formatted.isGroup
    };
  });
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
      identifyRealtimeStation(true);
    });

    socket.addEventListener('message', handleRealtimeMessage);

    socket.addEventListener('close', () => {
      if (realtimeSocket === socket) {
        realtimeSocket = undefined;
      }
      lastIdentifySignature = '';
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

function hideNavigationFeedback() {
  if (!navigationFeedbackEl) {
    return;
  }

  navigationFeedbackEl.classList.remove('is-visible');
  navigationFeedbackHideTimeout = window.setTimeout(() => {
    navigationFeedbackHideTimeout = undefined;
    navigationFeedbackEl.hidden = true;
    navigationFeedbackEl.textContent = '';
    navigationToneClasses.forEach((className) => {
      navigationFeedbackEl.classList.remove(className);
    });
  }, 220);
}

function showNavigationFeedback(message, tone = 'info', duration = 3200) {
  if (!navigationFeedbackEl) {
    return;
  }

  window.clearTimeout(navigationFeedbackTimeout);
  window.clearTimeout(navigationFeedbackHideTimeout);

  navigationToneClasses.forEach((className) => {
    navigationFeedbackEl.classList.remove(className);
  });

  const toneClass = tone === 'warning' ? 'app-toast--warning' : 'app-toast--info';
  navigationFeedbackEl.classList.add(toneClass);
  navigationFeedbackEl.textContent = message;
  navigationFeedbackEl.hidden = false;

  window.requestAnimationFrame(() => {
    navigationFeedbackEl.classList.add('is-visible');
  });

  navigationFeedbackTimeout = window.setTimeout(() => {
    hideNavigationFeedback();
  }, duration);
}

function getTopbarOffset() {
  if (!topbarEl) {
    return 0;
  }

  const rect = topbarEl.getBoundingClientRect();
  const offset = rect.height + 24;
  return Number.isFinite(offset) ? offset : 0;
}

function focusSection(section) {
  if (!section) {
    return;
  }

  window.requestAnimationFrame(() => {
    section.setAttribute('tabindex', '-1');
    section.focus({ preventScroll: true });
    window.setTimeout(() => {
      section.removeAttribute('tabindex');
    }, 250);
  });
}

function scrollToSection(sectionId) {
  const section = document.getElementById(sectionId);
  if (!section) {
    showNavigationFeedback('Essa seção ainda não está disponível.', 'warning');
    return false;
  }

  const topOffset = getTopbarOffset();
  const target = section.getBoundingClientRect().top + window.scrollY - topOffset;
  window.scrollTo({ top: Math.max(0, target), behavior: 'smooth' });
  focusSection(section);
  return true;
}

function updateActiveNavigation(activeAction) {
  navigationButtons.forEach((button) => {
    const action = button.dataset.action;
    const parent = button.closest('li');
    const isActive = action === activeAction;
    if (parent) {
      parent.classList.toggle('is-active', isActive);
    }
    if (isActive) {
      button.setAttribute('aria-current', 'page');
    } else {
      button.removeAttribute('aria-current');
    }
  });
}

const navigationHandlers = {
  dashboard: () => scrollToSection('summary'),
  relatorios: () => scrollToSection('runtimeStatus'),
  paineis: () => scrollToSection('board'),
  atendimentos: () => {
    const navigated = scrollToSection('board');
    if (navigated && searchInput) {
      window.setTimeout(() => {
        searchInput.focus();
      }, 400);
    }
    return navigated;
  },
  respostasRapidas: () => {
    showNavigationFeedback('As respostas rápidas estarão disponíveis em breve.', 'info');
    return false;
  },
  tagsCampanhas: () => {
    showNavigationFeedback('Gestão de tags e campanhas em desenvolvimento.', 'info');
    return false;
  },
  configuracoes: () => {
    toggleSettingsDrawer(true);
    return false;
  },
  integracoes: () => {
    showNavigationFeedback('Integrações avançadas estarão disponíveis em breve.', 'info');
    return false;
  },
  arquivos: () => {
    showNavigationFeedback('Central de arquivos será lançada em uma atualização futura.', 'info');
    return false;
  },
};

function handleNavigationAction(action) {
  if (!action) {
    return;
  }

  const handler = navigationHandlers[action];
  if (!handler) {
    showNavigationFeedback('Esse recurso ainda não está disponível.', 'warning');
    return;
  }

  const shouldHighlight = handler();
  if (shouldHighlight !== false) {
    updateActiveNavigation(action);
  }
}

function registerNavigation() {
  if (!navigationButtons.length) {
    return;
  }

  navigationButtons.forEach((button) => {
    button.addEventListener('click', () => {
      handleNavigationAction(button.dataset.action);
    });
  });

  const currentActive = navigationButtons.find((button) => {
    return button.closest('li')?.classList.contains('is-active');
  });

  updateActiveNavigation(currentActive?.dataset.action || 'dashboard');
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
  filterPrivateInput?.addEventListener('change', (event) => {
    state.filters.privateOnly = event.target.checked;
    renderSummary();
    renderFilters();
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
  resetWhatsappButton?.addEventListener('click', handleResetWhatsappSession);
  resetFiltersButton?.addEventListener('click', resetFilters);
  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape' && settingsOverlay?.classList.contains('is-open')) {
      toggleSettingsDrawer(false);
    }
  });

  registerNavigation();
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
