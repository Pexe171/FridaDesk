import fs from 'fs';
import path from 'path';
import os from 'os';
import { Database } from '../src/db.js';

function tempDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'fridadesk-test-'));
}

test('cria tabelas e aplica retenção', async () => {
  const dir = tempDir();
  const dbPath = path.join(dir, 'db.sqlite');
  const db = new Database({ dbPath, retention: { maxExecutions: 2 } });
  await db.init();
  // inserir 3 execuções
  const base = {
    script_id: 1,
    device_serial: 'ABC',
    process: 'proc',
    spawn: 'spawn',
    status: 'ok',
    logs_path: '/tmp/log',
    result: 'done',
  };
  await db.insertExecution({
    ...base,
    started_at: '2024-01-01',
    ended_at: '2024-01-01',
  });
  await db.insertExecution({
    ...base,
    started_at: '2024-01-02',
    ended_at: '2024-01-02',
  });
  await db.insertExecution({
    ...base,
    started_at: '2024-01-03',
    ended_at: '2024-01-03',
  });
  const stmt = db.db.prepare('SELECT count(*) as c FROM executions');
  stmt.step();
  const { c } = stmt.getAsObject();
  expect(c).toBe(2);
  stmt.free();
});

test('exporta e importa base de dados', async () => {
  const dir = tempDir();
  const dbPath = path.join(dir, 'db.sqlite');
  const db = new Database({ dbPath });
  await db.init();
  await db.insertExecution({
    script_id: 1,
    device_serial: 'XYZ',
    process: 'p',
    spawn: 's',
    started_at: '2024-02-01',
    ended_at: '2024-02-01',
    status: 'ok',
    logs_path: '/tmp/log',
    result: 'r',
  });
  const exportFile = path.join(dir, 'backup.sqlite');
  db.exportDatabase(exportFile);
  // importar em novo local
  const newDir = tempDir();
  const importedPath = path.join(newDir, 'db.sqlite');
  Database.importDatabase(exportFile, importedPath);
  const db2 = new Database({ dbPath: importedPath });
  await db2.init();
  const stmt = db2.db.prepare('SELECT count(*) as c FROM executions');
  stmt.step();
  const { c } = stmt.getAsObject();
  expect(c).toBe(1);
  stmt.free();
});

test('exporta execução para JSONL e TXT', async () => {
  const dir = tempDir();
  const dbPath = path.join(dir, 'db.sqlite');
  const db = new Database({ dbPath });
  await db.init();
  await db.insertExecution({
    script_id: 1,
    device_serial: 'SER',
    process: 'p',
    spawn: 's',
    started_at: '2024-03-01',
    ended_at: '2024-03-01',
    status: 'ok',
    logs_path: '/tmp/log',
    result: 'r',
  });
  const jsonl = db.exportExecution(1, 'jsonl');
  const txt = db.exportExecution(1, 'txt');
  expect(fs.existsSync(jsonl)).toBe(true);
  expect(fs.existsSync(txt)).toBe(true);
});
