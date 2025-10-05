const state = {
  categories: [],
  tasks: [],
  colors: new Map()
};

const summaryEl = document.getElementById('summary');
const boardEl = document.getElementById('board');
const refreshButton = document.getElementById('refreshTasks');
const lastUpdateEl = document.getElementById('lastUpdate');
const taskTemplate = document.getElementById('task-card');

async function fetchJson(url, options) {
  const response = await fetch(url, options);
  if (!response.ok) {
    const payload = await response.json().catch(() => ({}));
    const message = payload.message || 'Não foi possível completar a operação.';
    throw new Error(message);
  }
  return response.json();
}

function renderSummary() {
  summaryEl.innerHTML = '';
  const total = state.tasks.length;
  const openTasks = state.tasks.filter((task) => task.status === 'Aberto').length;
  const closedTasks = state.tasks.filter((task) => task.status === 'Concluído').length;

  const cards = [
    { label: 'Tarefas registradas', value: total },
    { label: 'Em atendimento', value: openTasks },
    { label: 'Concluídas', value: closedTasks }
  ];

  for (const card of cards) {
    const el = document.createElement('article');
    el.className = 'summary-card';
    el.innerHTML = `<span>${card.label}</span><strong>${card.value}</strong>`;
    summaryEl.appendChild(el);
  }
}

function renderBoard() {
  boardEl.innerHTML = '';
  const categories = state.categories.length ? state.categories : [{ name: 'Geral', color: '#546E7A' }];

  categories.forEach((category) => {
    const column = document.createElement('section');
    column.className = 'column';
    column.style.setProperty('border-top', `6px solid ${category.color || '#546E7A'}`);

    const header = document.createElement('header');
    const title = document.createElement('h2');
    title.textContent = category.name;
    const amount = document.createElement('span');
    const categoryTasks = state.tasks.filter((task) => task.category === category.name && task.status !== 'Concluído');
    amount.textContent = `${categoryTasks.length} em aberto`;

    header.appendChild(title);
    header.appendChild(amount);

    const list = document.createElement('div');
    list.className = 'task-list';

    if (!categoryTasks.length) {
      const empty = document.createElement('p');
      empty.className = 'empty-message';
      empty.textContent = 'Nenhum atendimento pendente.';
      list.appendChild(empty);
    } else {
      categoryTasks.forEach((task) => {
        const card = taskTemplate.content.firstElementChild.cloneNode(true);
        card.querySelector('.task-number').textContent = task.number;
        card.querySelector('.task-status').textContent = task.status;
        card.querySelector('.task-message').textContent = task.message;
        card.querySelector('.task-analyst').textContent = task.analyst ? `Responsável: ${task.analyst}` : 'Analista em definição';
        const button = card.querySelector('.task-complete');
        button.addEventListener('click', () => concludeTask(task));
        list.appendChild(card);
      });
    }

    column.appendChild(header);
    column.appendChild(list);
    boardEl.appendChild(column);
  });
}

async function concludeTask(task) {
  if (!confirm(`Marcar atendimento ${task.id} como concluído?`)) {
    return;
  }
  try {
    await fetchJson(`/api/tasks/${task.id}/complete`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ analyst: task.analyst })
    });
    await loadTasks(true);
  } catch (error) {
    alert(error.message);
  }
}

async function loadCategories() {
  try {
    const data = await fetchJson('/api/keywords');
    state.categories = data.categories;
    state.categories.forEach((category) => state.colors.set(category.name, category.color));
  } catch (error) {
    console.error('Erro ao carregar categorias', error);
  }
}

async function loadTasks(refresh = false) {
  const query = refresh ? '?refresh=true' : '';
  const data = await fetchJson(`/api/tasks${query}`);
  state.tasks = data.tasks;
  renderSummary();
  renderBoard();
  const now = new Date();
  lastUpdateEl.textContent = `Última atualização: ${now.toLocaleTimeString('pt-BR')}`;
}

async function bootstrap() {
  await loadCategories();
  await loadTasks(true);
}

refreshButton.addEventListener('click', () => loadTasks(true));
setInterval(() => loadTasks(true).catch(() => {}), 15000);

bootstrap().catch((error) => {
  console.error('Erro ao iniciar painel', error);
});
