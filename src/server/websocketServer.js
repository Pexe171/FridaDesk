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
  getRuntimeStatus,
  onClientsChanged
}) {
  const wss = new WebSocketServer({ server, path: '/ws' });
  const clientsMetadata = new Map();

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

  function summarizeClients() {
    const connectedClients = Array.from(wss.clients).filter((client) => client.readyState === OPEN_STATE).length;
    const stations = Array.from(clientsMetadata.values()).map((metadata) => ({
      id: metadata.id,
      name: metadata.name,
      analystName: metadata.analystName,
      session: metadata.session,
      hostname: metadata.hostname,
      connectedAt: metadata.connectedAt,
      lastSeenAt: metadata.lastSeenAt
    }));
    return { clients: connectedClients, stations };
  }

  function emitClientSummary() {
    const summary = summarizeClients();
    if (typeof onClientsChanged === 'function') {
      onClientsChanged(summary);
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
    const metadata = {
      id: `station-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
      name: 'Estação sem identificação',
      analystName: '',
      session: '',
      hostname: '',
      connectedAt: Date.now(),
      lastSeenAt: Date.now()
    };
    clientsMetadata.set(ws, metadata);
    ws.isAlive = true;
    ws.on('pong', () => {
      ws.isAlive = true;
      const currentMetadata = clientsMetadata.get(ws);
      if (currentMetadata) {
        currentMetadata.lastSeenAt = Date.now();
      }
    });
    ws.on('message', (raw) => {
      try {
        const message = JSON.parse(raw);
        if (message?.type === 'identify') {
          const currentMetadata = clientsMetadata.get(ws);
          if (currentMetadata) {
            currentMetadata.name = message.payload?.station || message.payload?.name || currentMetadata.name;
            currentMetadata.analystName = message.payload?.analystName || '';
            currentMetadata.session = message.payload?.session || '';
            currentMetadata.hostname = message.payload?.hostname || '';
            currentMetadata.version = message.payload?.version || '';
            currentMetadata.lastSeenAt = Date.now();
            emitClientSummary();
          }
        }
      } catch (error) {
        console.warn('Mensagem recebida no WebSocket ignorada por erro de parsing:', error.message);
      }
    });
    sendInitialState(ws);
    emitClientSummary();
    ws.on('close', () => {
      clientsMetadata.delete(ws);
      emitClientSummary();
    });
  });

  const heartbeat = setInterval(() => {
    wss.clients.forEach((client) => {
      if (client.isAlive === false) {
        client.terminate();
        clientsMetadata.delete(client);
        emitClientSummary();
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
    clientsMetadata.clear();
    wss.close();
  }

  return {
    notifyRuntimeStatus: notifyStatus,
    broadcast,
    close
  };
}
