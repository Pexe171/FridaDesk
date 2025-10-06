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
  getRuntimeStatus
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
