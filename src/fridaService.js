// Autor: Pexe (instagram: @David.devloli)
import { getClient } from './adbService.js';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { spawn as cpSpawn } from 'child_process';
import https from 'https';
import frida from 'frida';

const FRIDA_VERSION = '17.2.17';

function readAll(stream) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    stream.on('data', (c) => chunks.push(c));
    stream.on('end', () => resolve(Buffer.concat(chunks).toString().trim()));
    stream.on('error', reject);
  });
}

async function detectArch(id) {
  const client = await getClient();
  const stream = await client.shell(id, 'getprop ro.product.cpu.abi');
  return await readAll(stream);
}

function download(url, dest) {
  return new Promise((resolve, reject) => {
    const file = fs.createWriteStream(dest);
    https
      .get(url, (res) => {
        res.pipe(file);
        file.on('finish', () => file.close(resolve));
      })
      .on('error', (err) => {
        fs.unlink(dest, () => reject(err));
      });
  });
}

async function downloadFridaServer(arch) {
  const tmpDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'frida-'));
  const xzName = `frida-server-${FRIDA_VERSION}-android-${arch}.xz`;
  const url = `https://github.com/frida/frida/releases/download/${FRIDA_VERSION}/${xzName}`;
  const xzPath = path.join(tmpDir, xzName);
  await download(url, xzPath);
  await new Promise((res, rej) => {
    const proc = cpSpawn('xz', ['-d', xzPath]);
    proc.on('exit', (code) =>
      code === 0 ? res() : rej(new Error('xz falhou'))
    );
  });
  return path.join(tmpDir, `frida-server-${FRIDA_VERSION}-android-${arch}`);
}

export async function installFridaServer(id) {
  const client = await getClient();
  const arch = await detectArch(id);
  const localPath = await downloadFridaServer(arch);
  await client.push(
    id,
    fs.createReadStream(localPath),
    '/data/local/tmp/frida-server'
  );
  await client.shell(id, 'chmod 755 /data/local/tmp/frida-server');
}

export async function startFridaServer(id) {
  const client = await getClient();
  await client.shell(id, '/data/local/tmp/frida-server >/dev/null 2>&1 &');
}

export async function isFridaRunning(id) {
  const client = await getClient();
  try {
    const stream = await client.shell(id, 'pidof frida-server');
    const out = await readAll(stream);
    return out.length > 0;
  } catch {
    return false;
  }
}

export async function ensureFrida(id) {
  await installFridaServer(id);
  await startFridaServer(id);
}

// Funções básicas com frida-node
async function getFridaDevice(id) {
  return frida.getDevice(id);
}

export async function listProcesses(id) {
  const dev = await getFridaDevice(id);
  return dev.enumerateProcesses();
}

export async function spawnProcess(id, cmd) {
  const dev = await getFridaDevice(id);
  return dev.spawn(cmd);
}

export async function attach(id, pid) {
  const dev = await getFridaDevice(id);
  return dev.attach(pid);
}

export async function detach(session) {
  return session.detach();
}
