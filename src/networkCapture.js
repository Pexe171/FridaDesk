// DSL e agregador para eventos de rede HTTP/HTTPS
// Mantido por Pexe (instagram: David.devloli)

import { EventEmitter } from 'events';

/**
 * @typedef {Object} NetEvent
 * @property {string} type - 'http.request' ou 'http.response'
 * @property {string} execId - identificador único da requisição
 * @property {number} ts - timestamp em ms
 * @property {number} pid
 * @property {number} tid
 * @property {'java'|'native'} api
 * @property {string} [lib] - biblioteca de origem (OkHttp, libssl.so...)
 * @property {string} [url]
 * @property {string} [method]
 * @property {Object} [headers]
 * @property {string} [body]
 * @property {number} [status]
 * @property {number} [latencyMs]
 * @property {'out'|'in'} direction
 */

/**
 * Classe responsável por receber eventos via Frida e calcular métricas.
 * Opcionalmente realiza mascaramento de dados sensíveis e corta payloads.
 */
export class NetworkCapture extends EventEmitter {
  constructor({ maskKeys = [], payloadLimit = 0 } = {}) {
    super();
    this.events = [];
    this.maskKeys = maskKeys.map((k) => k.toLowerCase());
    this.payloadLimit = payloadLimit;
    this.pending = new Map(); // execId -> ts
    this.latencies = [];
    this.errors = 0;
  }

  /**
   * Adiciona evento bruto vindo do script Frida.
   * @param {NetEvent} evt
   */
  addEvent(evt) {
    const safe = this._sanitize(evt);
    this.events.push(safe);
    if (safe.type === 'http.request') {
      this.pending.set(safe.execId, safe.ts);
    } else if (safe.type === 'http.response') {
      const start = this.pending.get(safe.execId);
      if (start !== undefined) {
        const latency = safe.ts - start;
        safe.latencyMs = latency;
        this.latencies.push(latency);
        this.pending.delete(safe.execId);
      }
      if (typeof safe.status === 'number' && safe.status >= 400) {
        this.errors += 1;
      }
    }
    this.emit('event', safe);
  }

  /**
   * Retorna métricas agregadas das requisições capturadas.
   */
  getMetrics() {
    const total = this.latencies.length;
    const avg = total ? this.latencies.reduce((a, b) => a + b, 0) / total : 0;
    const sorted = [...this.latencies].sort((a, b) => a - b);
    const p95 = total
      ? sorted[
          Math.min(sorted.length - 1, Math.floor(0.95 * (sorted.length - 1)))
        ]
      : 0;
    const errorRate = total ? this.errors / total : 0;
    return { total, avg, p95, errorRate };
  }

  /**
   * Converte eventos para linhas JSON (JSONL).
   */
  toJSONL() {
    return this.events.map((e) => JSON.stringify(e)).join('\n');
  }

  /**
   * Converte eventos para formato HAR 1.2 simples.
   */
  toHAR() {
    const entries = [];
    for (const evt of this.events) {
      if (evt.type === 'http.request') {
        const entry = {
          startedDateTime: new Date(evt.ts).toISOString(),
          time: 0,
          request: {
            method: evt.method || '',
            url: evt.url || '',
            headers: this._headersArray(evt.headers),
            bodySize: evt.body ? evt.body.length : 0,
            postData: evt.body ? { text: evt.body } : undefined,
          },
          response: {},
        };
        entries.push(entry);
        evt.__har = entry;
      } else if (evt.type === 'http.response' && evt.__har) {
        evt.__har.time = evt.latencyMs || 0;
        evt.__har.response = {
          status: evt.status || 0,
          headers: this._headersArray(evt.headers),
          content: evt.body ? { text: evt.body } : {},
        };
      }
    }
    return { log: { version: '1.2', creator: { name: 'FridaDesk' }, entries } };
  }

  _headersArray(obj = {}) {
    return Object.entries(obj).map(([name, value]) => ({ name, value }));
  }

  _sanitize(evt) {
    const clone = JSON.parse(JSON.stringify(evt));
    if (clone.headers) {
      for (const k of Object.keys(clone.headers)) {
        if (this.maskKeys.includes(k.toLowerCase())) {
          clone.headers[k] = '***';
        }
      }
    } else {
      clone.headers = {};
    }
    if (
      clone.body &&
      this.payloadLimit > 0 &&
      clone.body.length > this.payloadLimit
    ) {
      clone.body = clone.body.slice(0, this.payloadLimit);
    }
    return clone;
  }
}

export default NetworkCapture;
