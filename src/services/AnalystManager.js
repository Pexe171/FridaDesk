const ANALYST_SHEET = 'Analistas';

export class AnalystManager {
  constructor({ sheetsService }) {
    this.sheetsService = sheetsService;
    this.analysts = new Map();
  }

  async refreshAnalysts() {
    const { rows } = await this.sheetsService.getRows(ANALYST_SHEET);
    this.analysts.clear();
    rows.forEach((row, index) => {
      const [name, category, status] = row;
      const rowNumber = index + 2;
      const analyst = { id: rowNumber, name, category, status };
      this.analysts.set(name, analyst);
    });
    return Array.from(this.analysts.values());
  }

  listAnalysts() {
    return Array.from(this.analysts.values());
  }

  findAvailableAnalyst(category) {
    const normalizedCategory = category?.toLowerCase();
    return this.listAnalysts().find((analyst) => {
      return (
        analyst.status?.toLowerCase() === 'disponível' &&
        analyst.category?.toLowerCase() === normalizedCategory
      );
    });
  }

  isAnalystAvailableForCategory(name, category) {
    const analyst = this.analysts.get(name);
    if (!analyst) return false;
    return (
      analyst.status?.toLowerCase() === 'disponível' &&
      analyst.category?.toLowerCase() === category?.toLowerCase()
    );
  }

  async assignAnalyst(category, preferredName) {
    let analyst;
    if (preferredName && this.isAnalystAvailableForCategory(preferredName, category)) {
      analyst = this.analysts.get(preferredName);
    } else {
      analyst = this.findAvailableAnalyst(category);
    }

    if (!analyst) {
      return undefined;
    }

    await this.updateAnalystStatus(analyst.name, 'Ocupado');
    return this.analysts.get(analyst.name);
  }

  async updateAnalystStatus(name, status) {
    const analyst = this.analysts.get(name);
    if (!analyst) {
      throw new Error('Analista não encontrado');
    }
    const updated = { ...analyst, status };
    await this.sheetsService.updateRow(ANALYST_SHEET, analyst.id, [
      updated.name,
      updated.category,
      updated.status
    ]);
    this.analysts.set(name, updated);
    return updated;
  }
}
