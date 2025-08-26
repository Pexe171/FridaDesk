import { EventEmitter } from 'events';
import { DebugSession } from '../src/debugSession.js';

class FakeScript extends EventEmitter {
  constructor() {
    super();
    this.message = { connect: (fn) => this.on('message', fn) };
  }
}

class FakeSignal extends EventEmitter {
  connect(fn) {
    this.on('signal', fn);
  }
  fire(arg) {
    this.emit('signal', arg);
  }
}

class FakeSession {
  constructor() {
    this.pid = 123;
    this.device = { id: 'dev' };
    this._detached = new FakeSignal();
    this._crashed = new FakeSignal();
    this.detached = { connect: (fn) => this._detached.connect(fn) };
    this.processCrashed = { connect: (fn) => this._crashed.connect(fn) };
  }
}

test('coleta mensagens e erros', async () => {
  const script = new FakeScript();
  const session = new FakeSession();
  const dbg = new DebugSession({ script, session });
  await dbg.enable();

  let detReason = null;
  dbg.on('detached', (r) => (detReason = r));

  script.emit('message', { type: 'send', payload: { foo: 'bar' } });
  script.emit('message', { type: 'error', stack: 'boom', description: 'x' });
  session._detached.fire('app');

  expect(dbg.lastPayload).toEqual({ foo: 'bar' });
  expect(dbg.errors).toHaveLength(1);
  expect(detReason).toBe('app');
  const rep = dbg.generateReport();
  expect(rep.mensagens).toBe(2);
});
