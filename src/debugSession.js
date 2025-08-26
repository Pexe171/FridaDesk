// Autor: Pexe (instagram: @David.devloli)
import { EventEmitter } from 'events';
import { getClient } from './adbService.js';

/**
 * Sessão de depuração responsável por centralizar eventos e métricas
 * de execução de scripts Frida.
 */
export class DebugSession extends EventEmitter {
  constructor({ script, session } = {}) {
    super();
    this.script = script;
    this.session = session || script?.session;
    this.errors = [];
    this.lastPayload = null;
    this.messageCount = 0;
    this.startTs = Date.now();
    this.attachMs = 0;
    this.spawnMs = 0;
    this.timeline = [];
  }

  /**
   * Inicia a escuta dos eventos do script e da sessão.
   */
  async enable() {
    if (this.script && this.script.message) {
      this.script.message.connect((msg, data) => this._onMessage(msg, data));
    }
    if (this.session) {
      if (this.session.detached) {
        this.session.detached.connect((reason) => {
          this._pushTimeline('detached', { reason });
          this.emit('detached', reason);
        });
      }
      if (this.session.processCrashed) {
        this.session.processCrashed.connect(() => {
          this._pushTimeline('crashed');
          this.emit('crashed');
        });
      }
    }
  }

  _onMessage(message) {
    this.messageCount += 1;
    if (message.type === 'error') {
      this.errors.push({
        stack: message.stack,
        description: message.description,
        fileName: message.fileName,
        lineNumber: message.lineNumber,
        columnNumber: message.columnNumber,
        lastPayload: this.lastPayload,
      });
      const errInfo = this.errors[this.errors.length - 1];
      this._pushTimeline('error', errInfo);
      this.emit('script-error', errInfo);
    } else {
      this.lastPayload = message.payload;
      this._pushTimeline(message.type, message.payload);
    }
    this.emit('message', message);
  }

  _pushTimeline(type, data = {}) {
    this.timeline.push({ ts: Date.now(), type, ...data });
  }

  /**
   * Registra o tempo gasto para attach.
   */
  markAttach(start) {
    this.attachMs = Date.now() - start;
  }

  /**
   * Registra o tempo gasto para spawn.
   */
  markSpawn(start) {
    this.spawnMs = Date.now() - start;
  }

  /**
   * Taxa de mensagens por segundo.
   */
  get messagesPerSecond() {
    const dur = (Date.now() - this.startTs) / 1000;
    return dur > 0 ? this.messageCount / dur : 0;
  }

  /**
   * Tenta obter uso de CPU do processo via ADB.
   */
  async getCpuUsage() {
    if (!this.session || !this.session.device || !this.session.pid) return null;
    try {
      const client = await getClient();
      if (!client) return null;
      const stream = await client.shell(
        this.session.device.id,
        `top -b -n 1 -p ${this.session.pid} | tail -1`
      );
      const output = await new Promise((resolve) => {
        let data = '';
        stream.on('data', (c) => (data += c));
        stream.on('end', () => resolve(data.trim()));
      });
      return output;
    } catch (e) {
      return null;
    }
  }

  /**
   * Gera relatório final da execução.
   * @param {Object} [networkCapture] instância de NetworkCapture
   */
  generateReport(networkCapture) {
    return {
      duracaoMs: Date.now() - this.startTs,
      mensagens: this.messageCount,
      taxaMensagens: this.messagesPerSecond,
      erros: this.errors,
      attachMs: this.attachMs,
      spawnMs: this.spawnMs,
      rede: networkCapture ? networkCapture.getMetrics() : null,
      timeline: this.timeline,
    };
  }
}

export default DebugSession;
