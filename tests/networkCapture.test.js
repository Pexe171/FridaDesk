import { NetworkCapture } from '../src/networkCapture.js';

describe('NetworkCapture', () => {
  test('mascara e calcula métricas', () => {
    const cap = new NetworkCapture({
      maskKeys: ['Authorization'],
      payloadLimit: 10,
    });
    cap.addEvent({
      type: 'http.request',
      execId: '1',
      ts: 0,
      pid: 1,
      tid: 1,
      api: 'java',
      lib: 'OkHttp',
      url: 'https://exemplo',
      method: 'GET',
      headers: { Authorization: 'segredo', Foo: 'Bar' },
      body: '123456789012345',
      direction: 'out',
    });
    cap.addEvent({
      type: 'http.response',
      execId: '1',
      ts: 100,
      pid: 1,
      tid: 1,
      api: 'java',
      lib: 'OkHttp',
      status: 200,
      headers: {},
      direction: 'in',
    });
    const eventos = cap.events;
    expect(eventos[0].headers.Authorization).toBe('***');
    expect(eventos[0].body).toBe('1234567890');
    const metrics = cap.getMetrics();
    expect(metrics.total).toBe(1);
    expect(metrics.errorRate).toBe(0);
    expect(metrics.avg).toBe(100);
    expect(metrics.p95).toBe(100);
  });
});
