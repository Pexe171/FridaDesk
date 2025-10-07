import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export function createHttpServer({
  taskManager,
  keywordClassifier,
  analystManager,
  settingsManager,
  getRuntimeStatus,
  resetWhatsappSession,
  logoutWhatsappSession,
  markAllTasksAsRead,
  completeAllTasks
}) {
  const app = express();
  app.use(express.json());

  const panelPath = path.resolve(__dirname, '../panel');
  app.use('/panel', express.static(panelPath));

  app.get('/api/settings', (req, res) => {
    res.json({
      settings: settingsManager.getSettings(),
      status: getRuntimeStatus?.() ?? {}
    });
  });

  app.put('/api/settings', async (req, res) => {
    try {
      const updated = await settingsManager.updateSettings(req.body ?? {});
      res.json({
        settings: updated,
        status: getRuntimeStatus?.() ?? {}
      });
    } catch (error) {
      res.status(500).json({
        message: 'Não foi possível atualizar as configurações.',
        details: error.message
      });
    }
  });

  app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', timestamp: Date.now() });
  });

  app.post('/api/whatsapp/reset-session', async (req, res) => {
    if (typeof resetWhatsappSession !== 'function') {
      return res.status(503).json({
        message: 'Reinício da sessão do WhatsApp não está disponível nesta instância.'
      });
    }
    try {
      const status = await resetWhatsappSession();
      res.json({
        message: 'Sessão do WhatsApp reiniciada. Escaneie o novo QR Code exibido no painel.',
        status: getRuntimeStatus?.() ?? {},
        whatsapp: status || {}
      });
    } catch (error) {
      if (error.code === 'NO_SESSION') {
        return res.status(400).json({
          message: 'Nenhuma sessão ativa configurada para reiniciar.'
        });
      }
      res.status(500).json({
        message: 'Não foi possível reiniciar a sessão do WhatsApp.',
        details: error.message
      });
    }
  });

  app.post('/api/whatsapp/logout', async (req, res) => {
    if (typeof logoutWhatsappSession !== 'function') {
      return res.status(503).json({
        message: 'Logout do WhatsApp não está disponível nesta instância.'
      });
    }
    try {
      const status = await logoutWhatsappSession();
      res.json({
        message: 'Sessão do WhatsApp encerrada. Configure novamente para reconectar.',
        status: getRuntimeStatus?.() ?? {},
        whatsapp: status || {}
      });
    } catch (error) {
      if (error.code === 'NO_SESSION') {
        return res.status(400).json({
          message: 'Nenhuma sessão ativa configurada para logout.'
        });
      }
      res.status(500).json({
        message: 'Não foi possível encerrar a sessão do WhatsApp.',
        details: error.message
      });
    }
  });

  app.get('/api/tasks', async (req, res) => {
    const { status } = req.query;
    try {
      if (req.query.refresh === 'true') {
        await taskManager.refreshTasks();
      }
      const tasks = taskManager.listTasks({ status });
      res.json({ tasks });
    } catch (error) {
      res.status(500).json({ message: 'Não foi possível listar as tarefas.', details: error.message });
    }
  });

  app.post('/api/tasks/mark-all-read', async (req, res) => {
    if (typeof markAllTasksAsRead !== 'function') {
      return res.status(503).json({ message: 'Marcação em lote não está disponível nesta instância.' });
    }
    try {
      const result = await markAllTasksAsRead();
      res.json({
        message:
          result.updated > 0
            ? `${result.updated} atendimentos marcados como lidos.`
            : 'Nenhum atendimento disponível para marcar como lido.',
        ...result
      });
    } catch (error) {
      res.status(500).json({
        message: 'Não foi possível marcar os atendimentos como lidos.',
        details: error.message
      });
    }
  });

  app.post('/api/tasks/complete-all', async (req, res) => {
    if (typeof completeAllTasks !== 'function') {
      return res.status(503).json({ message: 'Conclusão em lote não está disponível nesta instância.' });
    }
    try {
      const result = await completeAllTasks();
      res.json({
        message:
          result.updated > 0
            ? `${result.updated} atendimentos concluídos.`
            : 'Nenhum atendimento pendente para concluir.',
        ...result
      });
    } catch (error) {
      res.status(500).json({
        message: 'Não foi possível concluir os atendimentos.',
        details: error.message
      });
    }
  });

  app.post('/api/tasks/:id/complete', async (req, res) => {
    const { id } = req.params;
    const { analyst } = req.body ?? {};
    try {
      const task = await taskManager.completeTask(Number(id), { analyst });
      if (task.analyst) {
        try {
          await analystManager.updateAnalystStatus(task.analyst, 'Disponível');
        } catch (error) {
          console.warn('Não foi possível atualizar status do analista:', error.message);
        }
      }
      res.json({ task });
    } catch (error) {
      res.status(500).json({ message: 'Erro ao concluir tarefa.', details: error.message });
    }
  });

  app.get('/api/keywords', async (req, res) => {
    try {
      await keywordClassifier.load();
      res.json({ categories: keywordClassifier.listCategories() });
    } catch (error) {
      res.status(500).json({ message: 'Não foi possível carregar as palavras-chave.', details: error.message });
    }
  });

  app.post('/api/keywords', async (req, res) => {
    const { category, keywords, color } = req.body ?? {};
    if (!category || !keywords) {
      return res.status(400).json({ message: 'Informe a categoria e as palavras-chave.' });
    }
    try {
      await keywordClassifier.load();
      const updated = await keywordClassifier.addKeywords(category, keywords, color);
      res.status(201).json({ category: updated });
    } catch (error) {
      res.status(500).json({ message: 'Não foi possível atualizar as palavras-chave.', details: error.message });
    }
  });

  app.get('/api/analysts', async (req, res) => {
    try {
      await analystManager.refreshAnalysts();
      res.json({ analysts: analystManager.listAnalysts() });
    } catch (error) {
      res.status(500).json({ message: 'Não foi possível carregar os analistas.', details: error.message });
    }
  });

  app.post('/api/analysts/:name/status', async (req, res) => {
    const { name } = req.params;
    const { status } = req.body ?? {};
    if (!status) {
      return res.status(400).json({ message: 'Informe o status desejado.' });
    }
    try {
      await analystManager.refreshAnalysts();
      const updated = await analystManager.updateAnalystStatus(name, status);
      res.json({ analyst: updated });
    } catch (error) {
      res.status(500).json({ message: 'Não foi possível atualizar o analista.', details: error.message });
    }
  });

  app.get('/', (req, res) => {
    res.sendFile(path.join(panelPath, 'index.html'));
  });

  return app;
}
