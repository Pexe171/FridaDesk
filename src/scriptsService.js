import fs from 'fs';
import path from 'path';
import crypto from 'crypto';

/**
 * Serviço para gerenciamento de scripts locais e do CodeShare.
 * Mantido por Pexe (instagram: David.devloli)
 */
export class ScriptsService {
  constructor(db) {
    this.db = db;
  }

  checksum(source) {
    return crypto.createHash('sha256').update(source).digest('hex');
  }

  async add({ name, tags = [], source, origin, favorite = false }) {
    const checksum = this.checksum(source);
    return this.db.insertScript({
      name,
      tags,
      source,
      origin,
      favorite,
      checksum,
    });
  }

  async importFromFile(filePath, opts = {}) {
    const source = fs.readFileSync(filePath, 'utf8');
    const name = opts.name || path.basename(filePath);
    return this.add({
      name,
      tags: opts.tags || [],
      source,
      origin: `file:${filePath}`,
      favorite: opts.favorite,
    });
  }

  async importFromUrl(url, opts = {}) {
    const res = await fetch(url);
    if (!res.ok) throw new Error('Falha ao baixar script');
    const source = await res.text();
    const name = opts.name || path.basename(new URL(url).pathname) || 'script';
    return this.add({
      name,
      tags: opts.tags || [],
      source,
      origin: `url:${url}`,
      favorite: opts.favorite,
    });
  }

  async importFromCodeShare(identifier, opts = {}) {
    const rawUrl = `https://codeshare.frida.re/@${identifier}?format=raw`;
    const pageUrl = `https://codeshare.frida.re/@${identifier}`;
    const res = await fetch(rawUrl);
    if (!res.ok) throw new Error('Falha ao baixar script do CodeShare');
    const source = await res.text();
    let name = opts.name || identifier;
    let tags = opts.tags || [];
    try {
      const resPage = await fetch(pageUrl);
      if (resPage.ok) {
        const html = await resPage.text();
        const titleMatch = html.match(/<h1[^>]*>([^<]+)<\/h1>/i);
        if (titleMatch) name = titleMatch[1].trim();
        const tagMatch = html.match(/data-tags="([^"]*)"/i);
        if (tagMatch)
          tags = tagMatch[1]
            .split(',')
            .map((t) => t.trim())
            .filter(Boolean);
      }
    } catch (e) {
      // ignora falhas ao obter metadados
    }
    return this.add({
      name,
      tags,
      source,
      origin: `codeshare:${identifier}`,
      favorite: opts.favorite,
    });
  }

  list() {
    return this.db.listScripts();
  }

  setFavorite(id, favorite) {
    return this.db.updateScriptFavorite(id, favorite);
  }

  get(id) {
    return this.db.getScriptById(id);
  }
}
