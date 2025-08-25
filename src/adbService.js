// Autor: Pexe (instagram: @David.devloli)
import { createRequire } from 'module';

const require =
  typeof window !== 'undefined' && window.require
    ? window.require
    : createRequire(import.meta.url);

const path = require('path');
const { execSync } = require('child_process');
const fs = require('fs');

// Função para encontrar o caminho do adb
function findAdbPath() {
  // Tenta o caminho local primeiro
  const localAdbPath = path.join(
    process.cwd(),
    'bin',
    'adb',
    process.platform === 'win32' ? 'adb.exe' : 'adb'
  );
  if (fs.existsSync(localAdbPath)) {
    console.log('Using local ADB binary:', localAdbPath);
    return localAdbPath;
  }

  // Se não encontrar, tenta o PATH do sistema
  try {
    const cmd = process.platform === 'win32' ? 'where adb' : 'which adb';
    const systemAdbPath = execSync(cmd, { encoding: 'utf8' })
      .split('\n')[0]
      .trim();
    console.log('Using system ADB binary:', systemAdbPath);
    return systemAdbPath;
  } catch (e) {
    console.error('ADB binary not found locally or in system PATH.');
    return null;
  }
}

// Configura a variável de ambiente para o adbkit
const adbPath = findAdbPath();
if (adbPath) {
  process.env.ADB_BINARY = adbPath;
} else {
  console.error(
    'ADB binary could not be found. ADB functionality will be disabled.'
  );
}

const adbPromise = (
  typeof window !== 'undefined' && window.require
    ? Promise.resolve().then(() => window.require('adbkit'))
    : import(/* @vite-ignore */ 'adbkit').then((m) => m.default)
).catch((err) => {
  console.warn('Falha ao carregar adbkit:', err);
  return null;
});

let clientPromise;

export function getClient() {
  if (!clientPromise) {
    clientPromise = adbPromise.then((adb) => {
      if (adb) {
        console.log('adbkit module successfully loaded.');
        const client = adb.createClient({ host: '127.0.0.1', port: 5037 });
        console.log('ADB client created:', client);
        return client;
      } else {
        console.error('Failed to load adbkit module.');
        return null;
      }
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
