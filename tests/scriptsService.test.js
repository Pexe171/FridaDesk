import fs from 'fs';
import path from 'path';
import os from 'os';
import http from 'http';
import { Database } from '../src/db.js';
import { ScriptsService } from '../src/scriptsService.js';

function tempDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'fridadesk-test-'));
}

test('importa script de arquivo com metadados', async () => {
  const dir = tempDir();
  const dbPath = path.join(dir, 'db.sqlite');
  const db = new Database({ dbPath });
  await db.init();
  const service = new ScriptsService(db);
  const scriptPath = path.join(dir, 'teste.js');
  fs.writeFileSync(scriptPath, 'console.log("oi")');
  const id = await service.importFromFile(scriptPath, { tags: ['local'] });
  const script = db.getScriptById(id);
  expect(script.name).toBe('teste.js');
  expect(script.origin).toBe(`file:${scriptPath}`);
  expect(script.tags).toEqual(['local']);
  expect(script.favorite).toBe(0);
  expect(script.checksum).toBe(await service.checksum('console.log("oi")'));
});

test('importa script via URL e marca favorito', async () => {
  const dir = tempDir();
  const dbPath = path.join(dir, 'db.sqlite');
  const db = new Database({ dbPath });
  await db.init();
  const service = new ScriptsService(db);
  const server = http.createServer((req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('console.log("net")');
  });
  await new Promise((resolve) => server.listen(0, resolve));
  const { port } = server.address();
  const url = `http://localhost:${port}/script.js`;
  const id = await service.importFromUrl(url, {
    favorite: true,
    tags: ['remote'],
  });
  server.close();
  const script = db.getScriptById(id);
  expect(script.origin).toBe(`url:${url}`);
  expect(script.favorite).toBe(1);
  expect(script.tags).toEqual(['remote']);
});
