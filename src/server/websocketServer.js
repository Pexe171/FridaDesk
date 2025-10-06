import { WebSocketServer } from 'ws';

const OPEN_STATE = 1;

function safeSend(ws, message) {
  if (ws.readyState === OPEN_STATE) {
    ws.send(JSON.stringify(message));
  }
}

export function createWebSocketServer({
  server,
  taskManager,
  analystManager,
  settingsManager,
  getRuntimeStatus
}) {
  const wss = new WebSocketServer({ server, path: '/ws' });

  function broadcast(message) {
    const payload = JSON.stringify(message);
    wss.clients.forEach((client) => {
      if (client.readyState === OPEN_STATE) {
        client.send(payload);
      }
    });
  }

  function notifyStatus() {
    if (typeof getRuntimeStatus === 'function') {
      broadcast({ type: 'status', payload: getRuntimeStatus() });
    }
  }

  function sendInitialState(ws) {
    try {
      const tasks = taskManager?.listTasks?.() ?? [];
      const analysts = analystManager?.listAnalysts?.() ?? [];
      const settings = settingsManager?.getSettings?.() ?? {};
      const status = typeof getRuntimeStatus === 'function' ? getRuntimeStatus() : {};
      safeSend(ws, {
        type: 'init',
        payload: { tasks, analysts, settings, status }
      });
    } catch (error) {
      console.warn('Não foi possível enviar estado inicial pelo WebSocket:', error.message);
    }
  }

  wss.on('connection', (ws) => {
    ws.isAlive = true;
    ws.on('pong', () => {
      ws.isAlive = true;
    });
    sendInitialState(ws);
  });

  const heartbeat = setInterval(() => {
    wss.clients.forEach((client) => {
      if (client.isAlive === false) {
        client.terminate();
        return;
      }
      client.isAlive = false;
      client.ping();
    });
  }, 30000);

  const taskListener = (payload) => {
    broadcast({ type: 'tasks', payload });
  };
  const analystListener = (payload) => {
    broadcast({ type: 'analysts', payload });
  };
  const settingsListener = (payload) => {
    broadcast({ type: 'settings', payload });
  };

  taskManager?.on?.('tasks:updated', taskListener);
  analystManager?.on?.('analysts:updated', analystListener);
  settingsManager?.on?.('update', settingsListener);

  function close() {
    clearInterval(heartbeat);
    taskManager?.off?.('tasks:updated', taskListener);
    analystManager?.off?.('analysts:updated', analystListener);
    settingsManager?.off?.('update', settingsListener);
    wss.close();
  }

  return {
    notifyRuntimeStatus: notifyStatus,
    broadcast,
    close
  };
}
