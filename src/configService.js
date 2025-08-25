// Autor: Pexe (instagram: @David.devloli)
import fs from 'fs';
import path from 'path';
import { spawnSync } from 'child_process';

class ConfigService {
  constructor() {
    this.configFile = path.join(process.cwd(), 'config.json');
    this.config = {};
    this.load();
    this.detectDefaults();
  }

  load() {
    try {
      this.config = JSON.parse(fs.readFileSync(this.configFile, 'utf8'));
    } catch {
      this.config = {};
    }
  }

  save() {
    fs.writeFileSync(this.configFile, JSON.stringify(this.config, null, 2));
  }

  get(key) {
    return key ? this.config[key] : this.config;
  }

  set(key, value) {
    this.config[key] = value;
    this.save();
  }

  saveConfig(obj) {
    this.config = { ...this.config, ...obj };
    this.save();
  }

  detectDefaults() {
    if (!this.config.adbPath) {
      const adb = this.findExecutable('adb');
      if (adb) this.config.adbPath = adb;
    }
    if (!this.config.fridaPath) {
      const frida = this.findExecutable('frida-server');
      if (frida) this.config.fridaPath = frida;
    }
    this.save();
  }

  findExecutable(cmd) {
    const cmdName = process.platform === 'win32' ? 'where' : 'which';
    const result = spawnSync(cmdName, [cmd], { encoding: 'utf8' });
    if (result.status === 0) {
      return result.stdout.split(/\r?\n/).find(Boolean);
    }
    return null;
  }

  getAdbExecutable() {
    const local = path.join(
      process.cwd(),
      'bin',
      'adb',
      process.platform === 'win32' ? 'adb.exe' : 'adb'
    );
    if (fs.existsSync(local)) return local;
    if (this.config.adbPath && fs.existsSync(this.config.adbPath)) {
      return this.config.adbPath;
    }
    const detected = this.findExecutable('adb');
    if (detected) return detected;
    return 'adb';
  }
}

export const configService = new ConfigService();
export const getConfig = (key) => configService.get(key);
export const getAllConfig = () => configService.get();
export const setConfig = (key, value) => configService.set(key, value);
export const saveConfig = (obj) => configService.saveConfig(obj);
export const getAdbExecutable = () => configService.getAdbExecutable();
