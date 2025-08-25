// Captura de tráfego HTTP/HTTPS diretamente no processo
// Mantido por Pexe (instagram: David.devloli)
/* eslint-disable */

'use strict';

function enviar(tipo, dados) {
  send(Object.assign({ type: tipo }, dados));
}

function headersToJson(headers) {
  const out = {};
  const names = headers.names();
  for (let i = 0; i < names.size(); i++) {
    const n = names.get(i);
    out[n] = headers.get(n);
  }
  return out;
}

function bodyToString(body) {
  try {
    if (!body) return '';
    const Buffer = Java.use('okio.Buffer');
    const buffer = Buffer.$new();
    body.writeTo(buffer);
    return buffer.readUtf8();
  } catch (e) {
    return '';
  }
}

Java.perform(function () {
  // Hook em OkHttp
  try {
    const RealCall = Java.use('okhttp3.RealCall');
    RealCall.execute.implementation = function () {
      const execId = this.hashCode().toString();
      const req = this.request();
      const ts = Date.now();
      enviar('http.request', {
        execId,
        ts,
        pid: Process.id,
        tid: Process.getCurrentThreadId(),
        api: 'java',
        lib: 'OkHttp',
        url: req.url().toString(),
        method: req.method(),
        headers: headersToJson(req.headers()),
        body: bodyToString(req.body()),
        direction: 'out',
      });
      const res = this.execute();
      enviar('http.response', {
        execId,
        ts: Date.now(),
        pid: Process.id,
        tid: Process.getCurrentThreadId(),
        api: 'java',
        lib: 'OkHttp',
        status: res.code(),
        headers: headersToJson(res.headers()),
        body: bodyToString(res.body()),
        direction: 'in',
      });
      return res;
    };
  } catch (e) {
    // ignora se OkHttp não estiver presente
  }

  // Hook em HttpUrlConnection básico
  try {
    const HTTPSUrlConnection = Java.use('javax.net.ssl.HttpsURLConnection');
    HTTPSUrlConnection.getInputStream.implementation = function () {
      const execId = this.hashCode().toString();
      enviar('http.request', {
        execId,
        ts: Date.now(),
        pid: Process.id,
        tid: Process.getCurrentThreadId(),
        api: 'java',
        lib: 'HttpUrlConnection',
        url: this.getURL().toString(),
        method: this.getRequestMethod(),
        headers: {},
        direction: 'out',
      });
      const stream = this.getInputStream();
      enviar('http.response', {
        execId,
        ts: Date.now(),
        pid: Process.id,
        tid: Process.getCurrentThreadId(),
        api: 'java',
        lib: 'HttpUrlConnection',
        status: this.getResponseCode(),
        headers: {},
        direction: 'in',
      });
      return stream;
    };
  } catch (e) {
    // ignora
  }
});

// Hook nativo em SSL_read / SSL_write
['SSL_read', 'SSL_write'].forEach(function (name) {
  const addr = Module.findExportByName(null, name);
  if (!addr) return;
  Interceptor.attach(addr, {
    onEnter(args) {
      this.buf = args[1];
      this.len = args[2].toInt32();
      this.execId = this.threadId + ':' + Date.now();
      this.ts = Date.now();
    },
    onLeave(ret) {
      const size = ret.toInt32();
      if (size <= 0) return;
      const data = Memory.readByteArray(this.buf, size);
      enviar(name === 'SSL_write' ? 'http.request' : 'http.response', {
        execId: this.execId,
        ts: Date.now(),
        pid: Process.id,
        tid: this.threadId,
        api: 'native',
        lib: name,
        body: data ? data.toString('utf8') : '',
        direction: name === 'SSL_write' ? 'out' : 'in',
      });
    },
  });
});
