import 'dotenv/config';
import path from 'path';
import { fileURLToPath } from 'url';

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

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

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

async function bootstrap() {
  const { PORT = 3000 } = process.env;

  const baseTmpPath = path.resolve(__dirname, '../tmp');
  const settingsManager = new SettingsManager({
    storagePath: path.resolve(baseTmpPath, 'app-settings.json')
  });
  const currentSettings = await settingsManager.load();

  const keywordClassifier = new KeywordClassifier();
  await keywordClassifier.load();

  let runtimeStatus = {
    storage: areGoogleCredentialsConfigured(currentSettings) ? 'google' : 'local',
    googleConfigured: areGoogleCredentialsConfigured(currentSettings),
    whatsapp: { active: false, session: currentSettings.whatsappSession || '' },
    analystName: currentSettings.analystName || ''
  };

  let sheetsService = await createSheetsService(currentSettings, baseTmpPath);
  runtimeStatus = {
    ...runtimeStatus,
    storage: areGoogleCredentialsConfigured(currentSettings) ? 'google' : 'local',
    googleConfigured: areGoogleCredentialsConfigured(currentSettings)
  };

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
  async function applyWhatsAppSettings(settings) {
    const sessionId = (settings.whatsappSession || '').trim();
    if (!sessionId) {
      if (whatsappService) {
        await whatsappService.shutdown();
        whatsappService = undefined;
      }
      runtimeStatus = {
        ...runtimeStatus,
        whatsapp: { active: false, session: '' }
      };
      return;
    }

    if (whatsappService && whatsappService.sessionId === sessionId) {
      whatsappService.updateLocalAnalystName(settings.analystName);
      runtimeStatus = {
        ...runtimeStatus,
        whatsapp: { active: true, session: sessionId }
      };
      return;
    }

    if (whatsappService) {
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
      await whatsappService.init();
      console.log('Integração com WhatsApp iniciada.');
      runtimeStatus = {
        ...runtimeStatus,
        whatsapp: { active: true, session: sessionId }
      };
    } catch (error) {
      console.error('Não foi possível iniciar o cliente WhatsApp:', error);
      runtimeStatus = {
        ...runtimeStatus,
        whatsapp: { active: false, session: sessionId }
      };
    }
  }

  await applyWhatsAppSettings(currentSettings);

  const app = createHttpServer({
    taskManager,
    keywordClassifier,
    analystManager,
    settingsManager,
    getRuntimeStatus: () => ({ ...runtimeStatus })
  });
  const server = app.listen(PORT, () => {
    console.log(`Servidor HTTP disponível em http://localhost:${PORT}`);
    console.log('Acesse o painel em http://localhost:%s/panel', PORT);
  });

  async function reconfigureServices(updatedSettings) {
    const googleConfigured = areGoogleCredentialsConfigured(updatedSettings);
    const previousStorage = runtimeStatus.storage;
    const newService = await createSheetsService(updatedSettings, baseTmpPath);
    await taskManager.setSheetsService(newService);
    await analystManager.setSheetsService(newService);
    sheetsService = newService;
    runtimeStatus = {
      ...runtimeStatus,
      storage: googleConfigured ? 'google' : 'local',
      googleConfigured,
      analystName: updatedSettings.analystName || ''
    };

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
      .then(() => whatsappService?.shutdown())
      .finally(() => {
        server.close(() => process.exit(0));
      });
  };

  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

bootstrap().catch((error) => {
  console.error('Erro ao iniciar o CRM CCA:', error);
  process.exit(1);
});
