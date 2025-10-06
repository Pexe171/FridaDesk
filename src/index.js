import 'dotenv/config';
import path from 'path';
import os from 'os';
import { fileURLToPath } from 'url';
import readline from 'readline/promises';
import { stdin as input, stdout as output } from 'node:process';

import { KeywordClassifier } from './services/KeywordClassifier.js';
import { GoogleSheetsService } from './services/GoogleSheetsService.js';
import { LocalSheetsService } from './services/LocalSheetsService.js';
import { TaskManager } from './services/TaskManager.js';
import { AnalystManager } from './services/AnalystManager.js';
import { WhatsAppService } from './services/WhatsAppService.js';
import {
  SettingsManager,
  areGoogleCredentialsConfigured,
  resolveLocalStoragePath
} from './services/SettingsManager.js';
import { createHttpServer } from './server/httpServer.js';
import { createWebSocketServer } from './server/websocketServer.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

function createWhatsappRuntime(session = '') {
  return {
    active: false,
    session: session || '',
    connected: false,
    initializing: false,
    qr: null,
    qrImage: null,
    qrGeneratedAt: null,
    readyAt: null,
    messageCount: 0,
    lastMessageAt: null,
    error: null
  };
}

function createWebsocketRuntime() {
  return {
    clients: 0,
    stations: []
  };
}

async function createSheetsService(settings, basePath) {
  if (areGoogleCredentialsConfigured(settings)) {
    console.log('Integração com Google Sheets habilitada.');
    return new GoogleSheetsService({
      spreadsheetId: settings.googleSheetId,
      clientEmail: settings.googleClientEmail,
      privateKey: settings.googlePrivateKey,
      projectId: settings.googleProjectId
    });
  }

  const storagePath = resolveLocalStoragePath({
    basePath,
    whatsappSession: settings.whatsappSession
  });
  console.warn(
    'Credenciais do Google não encontradas. Utilizando armazenamento local em %s.',
    storagePath
  );
  const localService = new LocalSheetsService({ storagePath });
  await localService.load();
  return localService;
}

function getLanAccessUrls(port) {
  const interfaces = os.networkInterfaces();
  const addresses = new Set();

  Object.values(interfaces).forEach((iface = []) => {
    iface
      .filter((net) => net?.family === 'IPv4' && !net.internal)
      .forEach((net) => {
        addresses.add(`http://${net.address}:${port}`);
      });
  });

  return Array.from(addresses);
}

async function bootstrap() {
  const { PORT = 3000, HOST = '0.0.0.0' } = process.env;

  const baseTmpPath = path.resolve(__dirname, '../tmp');
  const settingsManager = new SettingsManager({
    storagePath: path.resolve(baseTmpPath, 'app-settings.json')
  });
  const currentSettings = await settingsManager.load();
  const runtimeStartedAt = Date.now();

  const keywordClassifier = new KeywordClassifier();
  await keywordClassifier.load();

  const initialGoogleConfigured = areGoogleCredentialsConfigured(currentSettings);
  let runtimeStatus = {
    storage: initialGoogleConfigured ? 'google' : 'local',
    googleConfigured: initialGoogleConfigured,
    whatsapp: createWhatsappRuntime(currentSettings.whatsappSession),
    analystName: currentSettings.analystName || '',
    websocket: createWebsocketRuntime(),
    health: {
      status: 'ok',
      startedAt: runtimeStartedAt,
      lastUpdated: runtimeStartedAt
    }
  };

  let realtimeNotifier;

  function touchRuntime() {
    runtimeStatus = {
      ...runtimeStatus,
      health: {
        ...runtimeStatus.health,
        lastUpdated: Date.now()
      }
    };
    realtimeNotifier?.notifyRuntimeStatus();
  }

  function setStorageRuntime(googleConfiguredFlag, { notify = true } = {}) {
    runtimeStatus = {
      ...runtimeStatus,
      storage: googleConfiguredFlag ? 'google' : 'local',
      googleConfigured: googleConfiguredFlag
    };
    if (notify) {
      touchRuntime();
    }
  }

  function setWhatsappRuntime(partial = {}, { reset = false } = {}) {
    const session = partial.session ?? runtimeStatus.whatsapp.session;
    const base = reset ? createWhatsappRuntime(session) : runtimeStatus.whatsapp;
    runtimeStatus = {
      ...runtimeStatus,
      whatsapp: {
        ...base,
        ...partial,
        session: partial.session ?? base.session ?? session
      }
    };
    touchRuntime();
  }

  function setWebsocketRuntime(summary = {}) {
    runtimeStatus = {
      ...runtimeStatus,
      websocket: {
        clients: summary.clients ?? 0,
        stations: Array.isArray(summary.stations) ? summary.stations : []
      }
    };
    touchRuntime();
  }

  setStorageRuntime(initialGoogleConfigured, { notify: false });

  let sheetsService = await createSheetsService(currentSettings, baseTmpPath);

  const taskManager = new TaskManager({ sheetsService });
  const analystManager = new AnalystManager({ sheetsService });

  await Promise.all([taskManager.initialize(), analystManager.refreshAnalysts()]);

  let lastAnalystName = currentSettings.analystName || '';
  async function markAnalystAvailable(name) {
    if (!name) {
      return;
    }
    try {
      await analystManager.refreshAnalysts();
      await analystManager.updateAnalystStatus(name, 'Disponível');
      console.log(`Analista ${name} marcado como disponível.`);
    } catch (error) {
      console.warn(`Não foi possível atualizar o status do analista ${name}: ${error.message}`);
    }
  }

  await markAnalystAvailable(lastAnalystName);

  let whatsappService;
  let whatsappStatusListener;

  function detachWhatsappListener() {
    if (whatsappService && whatsappStatusListener) {
      whatsappService.off('status', whatsappStatusListener);
      whatsappStatusListener = undefined;
    }
  }

  async function applyWhatsAppSettings(settings) {
    const sessionId = (settings.whatsappSession || '').trim();
    if (!sessionId) {
      if (whatsappService) {
        detachWhatsappListener();
        await whatsappService.shutdown();
        whatsappService = undefined;
      }
      setWhatsappRuntime({ session: '', active: false, connected: false }, { reset: true });
      return;
    }

    if (whatsappService && whatsappService.sessionId === sessionId) {
      whatsappService.updateLocalAnalystName(settings.analystName);
      const currentStatus = whatsappService.getStatus?.();
      if (currentStatus) {
        setWhatsappRuntime({ ...currentStatus, session: sessionId });
      } else {
        setWhatsappRuntime({ session: sessionId, active: true });
      }
      return;
    }

    if (whatsappService) {
      detachWhatsappListener();
      await whatsappService.shutdown();
      whatsappService = undefined;
    }

    whatsappService = new WhatsAppService({
      keywordClassifier,
      taskManager,
      analystManager,
      sessionId,
      localAnalystName: settings.analystName
    });

    try {
      setWhatsappRuntime({ session: sessionId }, { reset: true });
      whatsappStatusListener = (status) => {
        setWhatsappRuntime({ ...status, session: sessionId });
      };
      whatsappService.on('status', whatsappStatusListener);
      await whatsappService.init();
    } catch (error) {
      console.error('Não foi possível iniciar o cliente WhatsApp:', error);
      setWhatsappRuntime({ session: sessionId, active: false, connected: false });
    }
  }

  await applyWhatsAppSettings(currentSettings);

  async function resetWhatsappSession() {
    if (!whatsappService) {
      const error = new Error('Nenhuma sessão ativa configurada para reiniciar.');
      error.code = 'NO_SESSION';
      throw error;
    }
    await whatsappService.resetSession();
    const status = whatsappService.getStatus?.();
    if (status) {
      setWhatsappRuntime({ ...status });
    }
    return status;
  }

  const app = createHttpServer({
    taskManager,
    keywordClassifier,
    analystManager,
    settingsManager,
    getRuntimeStatus: () => ({ ...runtimeStatus }),
    resetWhatsappSession
  });
  const server = app.listen(PORT, HOST, () => {
    const isWildcardHost = HOST === '0.0.0.0' || HOST === '::';
    const displayHost = isWildcardHost ? 'localhost' : HOST;

    console.log(`Servidor HTTP disponível em http://${displayHost}:${PORT}`);
    console.log('Acesse o painel em http://%s:%s/panel', displayHost, PORT);

    if (isWildcardHost) {
      const lanUrls = getLanAccessUrls(PORT);
      if (lanUrls.length > 0) {
        console.log('Endereços disponíveis na rede local:');
        lanUrls.forEach((url) => console.log(`  - ${url}`));
        console.log('Painel disponível em cada endereço usando o sufixo /panel.');
      }
    }
  });

  realtimeNotifier = createWebSocketServer({
    server,
    taskManager,
    analystManager,
    settingsManager,
    getRuntimeStatus: () => ({ ...runtimeStatus }),
    onClientsChanged: setWebsocketRuntime
  });
  realtimeNotifier.notifyRuntimeStatus();

  async function reconfigureServices(updatedSettings) {
    const googleConfigured = areGoogleCredentialsConfigured(updatedSettings);
    const previousStorage = runtimeStatus.storage;
    const newService = await createSheetsService(updatedSettings, baseTmpPath);
    await taskManager.setSheetsService(newService);
    await analystManager.setSheetsService(newService);
    sheetsService = newService;
    setStorageRuntime(googleConfigured, { notify: false });
    runtimeStatus = {
      ...runtimeStatus,
      analystName: updatedSettings.analystName || ''
    };
    touchRuntime();

    if (lastAnalystName && lastAnalystName !== updatedSettings.analystName) {
      await markAnalystAvailable(lastAnalystName);
    }

    if (updatedSettings.analystName) {
      await markAnalystAvailable(updatedSettings.analystName);
    }

    lastAnalystName = updatedSettings.analystName || '';

    if (previousStorage !== runtimeStatus.storage) {
      console.log('Serviço de planilha reconfigurado para %s.', runtimeStatus.storage);
    }

    await applyWhatsAppSettings(updatedSettings);
  }

  let applyingUpdate = Promise.resolve();
  settingsManager.on('update', (updatedSettings) => {
    applyingUpdate = applyingUpdate
      .then(() => reconfigureServices(updatedSettings))
      .catch((error) => {
        console.error('Erro ao aplicar configurações:', error);
      });
  });

  const shutdown = () => {
    console.log('Encerrando CRM CCA...');
    Promise.resolve()
      .then(() => applyingUpdate)
      .then(() => {
        detachWhatsappListener();
        return whatsappService?.shutdown();
      })
      .then(() => realtimeNotifier?.close())
      .finally(() => {
        server.close(() => process.exit(0));
      });
  };

  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

async function resolveRuntimeRole() {
  const roleFromEnv = (process.env.CRM_ROLE || process.env.CRM_MODE || '').trim().toLowerCase();
  const validRoles = new Set(['host', 'user']);

  if (validRoles.has(roleFromEnv)) {
    return roleFromEnv;
  }

  if (!process.stdin.isTTY) {
    console.log('Entrada não interativa detectada. Assumindo papel "host".');
    return 'host';
  }

  const rl = readline.createInterface({ input, output });
  try {
    let answer = '';
    do {
      answer = (await rl.question('Esta estação será o host ou um usuário? [host/user]: ')).trim().toLowerCase();
      if (!validRoles.has(answer)) {
        console.log('Resposta inválida. Informe "host" ou "user".');
      }
    } while (!validRoles.has(answer));

    return answer;
  } finally {
    rl.close();
  }
}

async function runUserMode() {
  const defaultHint = 'http://IP_DO_HOST:PORT/panel';
  let remoteAddress = (process.env.CRM_REMOTE || '').trim();

  if (!remoteAddress && process.stdin.isTTY) {
    const rl = readline.createInterface({ input, output });
    try {
      const answer = (await rl.question('Informe o endereço do host (ex.: http://192.168.0.10:3000): ')).trim();
      remoteAddress = answer || '';
    } finally {
      rl.close();
    }
  }

  const displayAddress = remoteAddress || defaultHint;

  console.log('Modo usuário selecionado.');
  console.log('Abra o navegador nesta máquina e acesse: %s', displayAddress);
  console.log('Certifique-se de que a estação host esteja com o servidor ativo via "npm run dev" ou "npm start".');
}

async function main() {
  const role = await resolveRuntimeRole();

  if (role === 'user') {
    await runUserMode();
    return;
  }

  await bootstrap();
}

main().catch((error) => {
  console.error('Erro ao iniciar o CRM CCA:', error);
  process.exit(1);
});
