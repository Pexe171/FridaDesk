import { EventEmitter } from 'events';
import { access, mkdir, readFile, writeFile } from 'fs/promises';
import { constants } from 'fs';
import path from 'path';

const DEFAULT_SETTINGS = {
  whatsappSession: 'default',
  analystName: '',
  googleSheetId: '',
  googleClientEmail: '',
  googlePrivateKey: '',
  googleProjectId: ''
};

export class SettingsManager extends EventEmitter {
  constructor({ storagePath } = {}) {
    super();
    this.storagePath =
      storagePath || path.resolve(process.cwd(), 'tmp', 'app-settings.json');
    this.settings = { ...DEFAULT_SETTINGS };
  }

  async ensureFile() {
    try {
      await access(this.storagePath, constants.F_OK);
    } catch {
      const dir = path.dirname(this.storagePath);
      await mkdir(dir, { recursive: true });
      await writeFile(
        this.storagePath,
        JSON.stringify(this.settings, null, 2),
        'utf-8'
      );
    }
  }

  sanitize(partial = {}) {
    const next = {};
    Object.keys(DEFAULT_SETTINGS).forEach((key) => {
      if (Object.prototype.hasOwnProperty.call(partial, key)) {
        const value = partial[key];
        next[key] = value == null ? '' : String(value);
      }
    });
    return next;
  }

  mergeSettings(partial = {}) {
    const sanitized = this.sanitize(partial);
    this.settings = {
      ...this.settings,
      ...sanitized
    };
    return this.getSettings();
  }

  async load() {
    await this.ensureFile();
    try {
      const content = await readFile(this.storagePath, 'utf-8');
      const parsed = JSON.parse(content);
      this.settings = { ...DEFAULT_SETTINGS, ...this.sanitize(parsed) };
    } catch (error) {
      console.warn('Não foi possível carregar configurações salvas. Usando padrão.');
      this.settings = { ...DEFAULT_SETTINGS };
    }
    return this.getSettings();
  }

  async save() {
    await writeFile(
      this.storagePath,
      JSON.stringify(this.settings, null, 2),
      'utf-8'
    );
  }

  getSettings() {
    return { ...this.settings };
  }

  async updateSettings(partial = {}) {
    const updated = this.mergeSettings(partial);
    await this.save();
    this.emit('update', updated);
    return updated;
  }
}

export function areGoogleCredentialsConfigured(settings) {
  return Boolean(
    settings.googleSheetId &&
      settings.googleClientEmail &&
      settings.googlePrivateKey
  );
}

export function resolveLocalStoragePath({
  basePath,
  whatsappSession
}) {
  const session = whatsappSession ? whatsappSession.trim() : 'default';
  return path.resolve(basePath, `local-sheet-${session || 'default'}.json`);
}
