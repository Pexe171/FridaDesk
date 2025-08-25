// Autor: Pexe (instagram: @David.devloli)
// Garante uso do adbkit em ambientes diferentes sem `top-level await`
import { createRequire } from 'module';

const require =
  typeof window !== 'undefined' && window.require
    ? window.require
    : createRequire(import.meta.url);

const path = require('path');
const { exec } = require('child_process');
const fs = require('fs');
const { fileURLToPath } = require('url');

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Função para encontrar o caminho do adb
function findAdbPath() {
  const localAdbPath = path.join(
    __dirname,
    '..',
    'bin',
    'adb',
    process.platform === 'win32' ? 'adb.exe' : 'adb'
  );
  if (fs.existsSync(localAdbPath)) {
    console.log('Using local ADB binary:', localAdbPath);
    return localAdbPath;
  }
  console.log('Local ADB binary not found, falling back to system PATH.');
  return 'adb';
}

const adbPath = findAdbPath();

const adbPromise = new Promise((resolve) => {
  if (process.env.NODE_ENV === 'test') {
    import(/* @vite-ignore */ 'adbkit')
      .then((m) => resolve(m.default))
      .catch((err) => {
        console.warn('Falha ao carregar adbkit:', err);
        resolve(null);
      });
    return;
  }

  exec(`"${adbPath}" version`, (err) => {
    if (err) {
      console.warn(
        'Falha ao encontrar o binário ADB no caminho:',
        adbPath,
        err
      );
      return resolve(null);
    }
    import(/* @vite-ignore */ 'adbkit')
      .then((m) => resolve(m.default))
      .catch((err) => {
        console.warn('Falha ao carregar adbkit:', err);
        resolve(null);
      });
  });
}).catch((err) => {
  console.warn('Falha ao carregar adbkit:', err);
  return null;
});

let clientPromise;

export function getClient() {
  if (!clientPromise) {
    clientPromise = adbPromise.then((adb) => {
      const client = adb ? adb.createClient({ bin: adbPath }) : null;
      console.log('Cliente ADB criado:', client);
      return client;
    });
  }
  return clientPromise;
}

// Cache simples para modelos de dispositivos
const deviceModelCache = {};

export async function listDevices() {
  const client = await getClient();
  const adb = await adbPromise;
  if (!client || !adb) {
    console.log('adbkit não disponível, retornando lista vazia');
    return [];
  }
  try {
    const devices = await client.listDevices();
    console.log('Dispositivos listados pelo adbkit:', devices);
    const result = await Promise.all(
      devices.map(async (device) => {
        let model = deviceModelCache[device.id];
        if (!model) {
          model = 'desconhecido';
          try {
            const stream = await client.shell(
              device.id,
              'getprop ro.product.model'
            );
            model = (await adb.util.readAll(stream)).toString().trim();
          } catch (e) {
            // Ignora erros ao obter modelo
          }
          deviceModelCache[device.id] = model;
        }
        return { id: device.id, type: device.type, model };
      })
    );
    // Remove dispositivos desconectados do cache
    Object.keys(deviceModelCache).forEach((id) => {
      if (!devices.find((d) => d.id === id)) delete deviceModelCache[id];
    });
    return result;
  } catch (e) {
    console.error('Erro ao listar dispositivos:', e);
    return [];
  }
}

export async function connectAdb(host, port = 5555) {
  const client = await getClient();
  if (!client) throw new Error('adbkit não disponível');
  return client.connect(host, port);
}

export async function autoConnectEmulators(start = 5555, end = 5585) {
  const client = await getClient();
  if (!client) return;
  for (let port = start; port <= end; port += 2) {
    try {
      await client.connect('127.0.0.1', port);
    } catch (e) {
      // Ignora portas sem emulador
    }
  }
}

export async function connectTcpip(id, host, port = 5555) {
  const client = await getClient();
  if (!client) throw new Error('adbkit não disponível');
  await client.tcpip(id, port);
  return client.connect(host, port);
}

export async function installApk(id, apkPath) {
  const client = await getClient();
  if (!client) throw new Error('adbkit não disponível');
  return client.install(id, apkPath);
}

export async function startLogcat(id) {
  const client = await getClient();
  if (!client) throw new Error('adbkit não disponível');
  return client.openLogcat(id);
}

export async function healthCheck(id) {
  const client = await getClient();
  const adb = await adbPromise;
  if (!client || !adb) return false;
  const stream = await client.shell(id, 'echo OK');
  const output = (await adb.util.readAll(stream)).toString().trim();
  return output === 'OK';
}
