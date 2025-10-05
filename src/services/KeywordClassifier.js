import { readFile, writeFile } from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export class KeywordClassifier {
  constructor(configPath = path.resolve(__dirname, '../config/keywords.json')) {
    this.configPath = configPath;
    this.defaultCategory = 'Geral';
    this.categories = [];
  }

  async load() {
    const content = await readFile(this.configPath, 'utf-8');
    const data = JSON.parse(content);
    this.defaultCategory = data.defaultCategory || 'Geral';
    this.categories = data.categories || [];
  }

  async save() {
    const data = {
      defaultCategory: this.defaultCategory,
      categories: this.categories
    };
    await writeFile(this.configPath, JSON.stringify(data, null, 2));
  }

  /**
   * Classifica o texto recebido em uma categoria com base nas palavras-chave configuradas.
   * @param {string} text
   * @returns {{ category: string, keyword?: string }}
   */
  classify(text = '') {
    const normalized = text.toLowerCase();

    for (const category of this.categories) {
      for (const keyword of category.keywords) {
        const normalizedKeyword = keyword.toLowerCase();
        if (normalized.includes(normalizedKeyword)) {
          return { category: category.name, keyword };
        }
      }
    }

    return { category: this.defaultCategory };
  }

  listCategories() {
    return this.categories.map(({ name, keywords, color }) => ({ name, keywords, color }));
  }

  getCategoryColor(name) {
    const found = this.categories.find((cat) => cat.name === name);
    return found?.color;
  }

  /**
   * Adiciona uma nova palavra-chave a uma categoria. Se a categoria não existir, ela será criada.
   * @param {string} categoryName
   * @param {string|string[]} keywords
   * @param {string} [color]
   */
  async addKeywords(categoryName, keywords, color) {
    const normalizedCategory = categoryName.trim();
    const list = Array.isArray(keywords) ? keywords : [keywords];
    let category = this.categories.find((cat) => cat.name === normalizedCategory);

    if (!category) {
      category = {
        name: normalizedCategory,
        color: color || '#546E7A',
        keywords: []
      };
      this.categories.push(category);
    } else if (color) {
      category.color = color;
    }

    for (const keyword of list) {
      const formatted = keyword.toLowerCase();
      if (!category.keywords.some((existing) => existing.toLowerCase() === formatted)) {
        category.keywords.push(keyword);
      }
    }

    await this.save();
    return category;
  }
}
