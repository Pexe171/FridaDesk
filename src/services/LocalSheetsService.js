import { readFile, writeFile, access, mkdir } from 'fs/promises';
import { constants } from 'fs';
import path from 'path';

const DEFAULT_SHEETS = {
  'Atendimentos CCA': [['Data', 'Número', 'Categoria', 'Mensagem', 'Status', 'Analista']],
  Analistas: [
    ['Nome', 'Categoria', 'Status'],
    ['Ana Silva', 'Crédito', 'Disponível'],
    ['Bruno Costa', 'Repasse', 'Disponível']
  ]
};

function cloneSheet(template) {
  return template.map((row) => [...row]);
}

export class LocalSheetsService {
  constructor({ storagePath }) {
    this.storagePath = storagePath || path.resolve(process.cwd(), 'tmp', 'local-sheet.json');
    this.data = {};
  }

  async ensureFile() {
    try {
      await access(this.storagePath, constants.F_OK);
    } catch {
      const dir = path.dirname(this.storagePath);
      await mkdir(dir, { recursive: true });
      await writeFile(this.storagePath, JSON.stringify(DEFAULT_SHEETS, null, 2));
    }
  }

  async load() {
    await this.ensureFile();
    const content = await readFile(this.storagePath, 'utf-8');
    this.data = JSON.parse(content);
  }

  async persist() {
    await writeFile(this.storagePath, JSON.stringify(this.data, null, 2));
  }

  ensureSheet(sheetName) {
    if (!this.data[sheetName]) {
      const template = DEFAULT_SHEETS[sheetName];
      this.data[sheetName] = template ? cloneSheet(template) : [[]];
    }
  }

  async getRows(sheetName) {
    if (!Object.keys(this.data).length) {
      await this.load();
    }
    this.ensureSheet(sheetName);
    const rows = this.data[sheetName];
    const [header = [], ...dataRows] = rows;
    return { header, rows: dataRows };
  }

  async appendRow(sheetName, values) {
    if (!Object.keys(this.data).length) {
      await this.load();
    }
    this.ensureSheet(sheetName);

    const rows = this.data[sheetName];
    const hasHeader = rows[0]?.length;
    if (!hasHeader) {
      throw new Error(`Cabeçalho da planilha ${sheetName} não foi definido.`);
    }

    rows.push(values);
    await this.persist();
    const rowNumber = rows.length;
    return { rowNumber, values };
  }

  async updateRow(sheetName, rowNumber, values) {
    if (!Object.keys(this.data).length) {
      await this.load();
    }
    this.ensureSheet(sheetName);
    const rows = this.data[sheetName];
    rows[rowNumber - 1] = values;
    await this.persist();
  }
}
