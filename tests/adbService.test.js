import { jest } from '@jest/globals';

let listDevices;
let connectTcpip;
let installApk;
let healthCheck;
let __client;

beforeAll(async () => {
  await jest.unstable_mockModule('adbkit', () => {
    const listDevices = jest
      .fn()
      .mockResolvedValue([{ id: 'device1', type: 'device' }]);
    const shell = jest
      .fn()
      .mockImplementation((id, cmd) =>
        Promise.resolve(Buffer.from(cmd.includes('getprop') ? 'Pixel 3' : 'OK'))
      );
    const tcpip = jest.fn().mockResolvedValue();
    const connect = jest.fn().mockResolvedValue('192.168.0.5:5555');
    const install = jest.fn().mockResolvedValue();
    const openLogcat = jest.fn();
    const readAll = (stream) => Promise.resolve(stream);
    const client = { listDevices, shell, tcpip, connect, install, openLogcat };
    return {
      __esModule: true,
      default: { createClient: () => client, util: { readAll } },
      __client: client,
    };
  });

  ({ listDevices, connectTcpip, installApk, healthCheck } = await import(
    '../src/adbService.js'
  ));
  ({ __client } = await import('adbkit'));
});

test('listDevices retorna modelo e status', async () => {
  const devices = await listDevices();
  expect(devices).toEqual([
    { id: 'device1', type: 'device', model: 'Pixel 3' },
  ]);
});

test('connectTcpip usa tcpip e connect', async () => {
  await connectTcpip('device1', '192.168.0.5', 5555);
  expect(__client.tcpip).toHaveBeenCalledWith('device1', 5555);
  expect(__client.connect).toHaveBeenCalledWith('192.168.0.5', 5555);
});

test('installApk chama client.install', async () => {
  await installApk('device1', '/tmp/app.apk');
  expect(__client.install).toHaveBeenCalledWith('device1', '/tmp/app.apk');
});

test('healthCheck confirma resposta OK', async () => {
  const ok = await healthCheck('device1');
  expect(ok).toBe(true);
});
