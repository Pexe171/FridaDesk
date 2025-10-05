import 'dotenv/config';
import path from 'path';
import { fileURLToPath } from 'url';

import { KeywordClassifier } from './services/KeywordClassifier.js';
import { GoogleSheetsService } from './services/GoogleSheetsService.js';
import { LocalSheetsService } from './services/LocalSheetsService.js';
import { TaskManager } from './services/TaskManager.js';
import { AnalystManager } from './services/AnalystManager.js';
import { WhatsAppService } from './services/WhatsAppService.js';
import { createHttpServer } from './server/httpServer.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function bootstrap() {
  const {
    PORT = 3000,
    GOOGLE_SHEET_ID,
    GOOGLE_CLIENT_EMAIL,
    GOOGLE_PRIVATE_KEY,
    GOOGLE_PROJECT_ID,
    WHATSAPP_SESSION = 'default',
    ANALYST_NAME
  } = process.env;

  const keywordClassifier = new KeywordClassifier();
  await keywordClassifier.load();

  let sheetsService;
  if (GOOGLE_SHEET_ID && GOOGLE_CLIENT_EMAIL && GOOGLE_PRIVATE_KEY) {
    sheetsService = new GoogleSheetsService({
      spreadsheetId: GOOGLE_SHEET_ID,
      clientEmail: GOOGLE_CLIENT_EMAIL,
      privateKey: GOOGLE_PRIVATE_KEY,
      projectId: GOOGLE_PROJECT_ID
    });
    console.log('Integração com Google Sheets habilitada.');
  } else {
    console.warn('Credenciais do Google não encontradas. Utilizando armazenamento local em tmp/.');
    const storagePath = path.resolve(__dirname, '../tmp', `local-sheet-${WHATSAPP_SESSION}.json`);
    sheetsService = new LocalSheetsService({ storagePath });
    await sheetsService.load();
  }

  const taskManager = new TaskManager({ sheetsService });
  const analystManager = new AnalystManager({ sheetsService });

  await Promise.all([taskManager.initialize(), analystManager.refreshAnalysts()]);

  if (ANALYST_NAME) {
    try {
      await analystManager.updateAnalystStatus(ANALYST_NAME, 'Disponível');
      console.log(`Analista ${ANALYST_NAME} marcado como disponível.`);
    } catch (error) {
      console.warn(`Não foi possível atualizar o status do analista ${ANALYST_NAME}: ${error.message}`);
    }
  }

  const app = createHttpServer({ taskManager, keywordClassifier, analystManager });
  const server = app.listen(PORT, () => {
    console.log(`Servidor HTTP disponível em http://localhost:${PORT}`);
    console.log('Acesse o painel em http://localhost:%s/panel', PORT);
  });

  const whatsappService = new WhatsAppService({
    keywordClassifier,
    taskManager,
    analystManager,
    sessionId: WHATSAPP_SESSION,
    localAnalystName: ANALYST_NAME
  });

  whatsappService
    .init()
    .then(() => {
      console.log('Integração com WhatsApp iniciada.');
    })
    .catch((error) => {
      console.error('Não foi possível iniciar o cliente WhatsApp:', error);
    });

  const shutdown = () => {
    console.log('Encerrando CRM CCA...');
    server.close(() => process.exit(0));
  };

  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

bootstrap().catch((error) => {
  console.error('Erro ao iniciar o CRM CCA:', error);
  process.exit(1);
});
