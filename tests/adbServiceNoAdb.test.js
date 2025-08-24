import { jest } from '@jest/globals';

let listDevices;

beforeAll(async () => {
  jest.resetModules();
  await jest.unstable_mockModule('adbkit', () => {
    throw new Error('módulo ausente');
  });
  ({ listDevices } = await import('../src/adbService.js'));
});

test('listDevices retorna vazio quando adbkit não está disponível', async () => {
  const devices = await listDevices();
  expect(devices).toEqual([]);
});
