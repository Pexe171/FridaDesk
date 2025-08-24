import initSqlJs from 'sql.js';
import { createRequire } from 'module';

// Garante acesso aos módulos nativos tanto no Electron quanto nos testes
const require =
  typeof window !== 'undefined' && window.require
    ? window.require
    : createRequire(import.meta.url);
const fs = require('fs');
const path = require('path');

/**
 * Gerenciador de banco de dados SQLite utilizando sql.js.
 * Mantido por Pexe (instagram: David.devloli)
 */
export class Database {
  constructor(options = {}) {
    const userDataDir =
      options.userDataDir || path.join(process.cwd(), 'userData');
    this.dbPath = options.dbPath || path.join(userDataDir, 'fridadesk.sqlite');
    this.exportDir = options.exportDir || path.join(userDataDir, 'exports');
    this.retention = options.retention || {
      maxExecutions: null,
      maxDays: null,
    };
    this.lock = Promise.resolve();
    this.SQL = null;
    this.db = null;
  }

  async init() {
    if (!this.SQL) {
      this.SQL = await initSqlJs({
        locateFile: (file) => path.resolve('node_modules/sql.js/dist', file),
      });
    }
    if (fs.existsSync(this.dbPath)) {
      const fileBuffer = fs.readFileSync(this.dbPath);
      this.db = new this.SQL.Database(fileBuffer);
    } else {
      fs.mkdirSync(path.dirname(this.dbPath), { recursive: true });
      this.db = new this.SQL.Database();
    }
    this.migrate();
    await this.save();
  }

  migrate() {
    const statements = `
      CREATE TABLE IF NOT EXISTS devices (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        serial TEXT UNIQUE,
        model TEXT,
        transport TEXT,
        status TEXT,
        last_seen TEXT
      );

      CREATE TABLE IF NOT EXISTS scripts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        tags TEXT,
        source TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS executions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        script_id INTEGER,
        device_serial TEXT,
        process TEXT,
        spawn TEXT,
        started_at TEXT,
        ended_at TEXT,
        status TEXT,
        logs_path TEXT,
        result TEXT,
        FOREIGN KEY(script_id) REFERENCES scripts(id)
      );

      CREATE INDEX IF NOT EXISTS idx_devices_serial ON devices(serial);
      CREATE INDEX IF NOT EXISTS idx_scripts_name ON scripts(name);
      CREATE INDEX IF NOT EXISTS idx_exec_script_id ON executions(script_id);
    `;
    this.db.exec(statements);
  }

  async save() {
    this.lock = this.lock.then(() => {
      const data = this.db.export();
      const buffer = Buffer.from(data);
      fs.writeFileSync(this.dbPath, buffer);
    });
    return this.lock;
  }

  insertExecution(exec) {
    const stmt = this.db.prepare(`INSERT INTO executions
      (script_id, device_serial, process, spawn, started_at, ended_at, status, logs_path, result)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`);
    stmt.run([
      exec.script_id,
      exec.device_serial,
      exec.process,
      exec.spawn,
      exec.started_at,
      exec.ended_at,
      exec.status,
      exec.logs_path,
      exec.result,
    ]);
    stmt.free();
    this.applyRetention();
    return this.save();
  }

  applyRetention() {
    const { maxExecutions, maxDays } = this.retention;
    if (maxExecutions) {
      this.db.exec(`
        DELETE FROM executions
        WHERE id NOT IN (
          SELECT id FROM executions ORDER BY started_at DESC LIMIT ${maxExecutions}
        );
      `);
    }
    if (maxDays) {
      this.db.exec(`
        DELETE FROM executions
        WHERE started_at < datetime('now', '-${maxDays} days');
      `);
    }
  }

  exportExecution(id, format = 'jsonl') {
    const stmt = this.db.prepare('SELECT * FROM executions WHERE id = ?');
    const result = stmt.getAsObject([id]);
    stmt.free();
    fs.mkdirSync(this.exportDir, { recursive: true });
    const ext = format === 'jsonl' ? 'jsonl' : 'txt';
    const filePath = path.join(this.exportDir, `exec-${id}.${ext}`);
    const content =
      format === 'jsonl'
        ? JSON.stringify(result) + '\n'
        : Object.entries(result)
            .map(([k, v]) => `${k}: ${v}`)
            .join('\n');
    fs.writeFileSync(filePath, content);
    return filePath;
  }

  exportDatabase(destination) {
    const data = this.db.export();
    const buffer = Buffer.from(data);
    fs.writeFileSync(destination, buffer);
  }

  static importDatabase(source, destination) {
    const data = fs.readFileSync(source);
    fs.mkdirSync(path.dirname(destination), { recursive: true });
    fs.writeFileSync(destination, data);
  }
}
