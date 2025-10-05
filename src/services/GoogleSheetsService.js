import { google } from 'googleapis';

export class GoogleSheetsService {
  constructor({ spreadsheetId, clientEmail, privateKey, projectId }) {
    if (!spreadsheetId) {
      throw new Error('GOOGLE_SHEET_ID não informado.');
    }
    if (!clientEmail || !privateKey) {
      throw new Error('Credenciais do Google não foram configuradas.');
    }

    const formattedKey = privateKey.replace(/\\n/g, '\n');

    this.auth = new google.auth.GoogleAuth({
      credentials: {
        client_email: clientEmail,
        private_key: formattedKey,
        project_id: projectId
      },
      scopes: ['https://www.googleapis.com/auth/spreadsheets']
    });
    this.spreadsheetId = spreadsheetId;
    this.clientPromise = this.auth.getClient();
    this.sheets = google.sheets({ version: 'v4', auth: this.auth });
  }

  async appendRow(sheetName, values) {
    const client = await this.clientPromise;
    const response = await this.sheets.spreadsheets.values.append({
      spreadsheetId: this.spreadsheetId,
      range: `${sheetName}!A:F`,
      valueInputOption: 'USER_ENTERED',
      insertDataOption: 'INSERT_ROWS',
      includeValuesInResponse: true,
      requestBody: {
        values: [values]
      },
      auth: client
    });

    const updatedRange = response.data.updates?.updatedRange;
    const row = updatedRange ? Number(updatedRange.split('!')[1].match(/\d+/)[0]) : undefined;
    return { rowNumber: row, values: response.data.updates?.updatedData?.values?.[0] ?? values };
  }

  async updateRow(sheetName, rowNumber, values) {
    const client = await this.clientPromise;
    const range = `${sheetName}!A${rowNumber}:F${rowNumber}`;
    await this.sheets.spreadsheets.values.update({
      spreadsheetId: this.spreadsheetId,
      range,
      valueInputOption: 'USER_ENTERED',
      requestBody: { values: [values] },
      auth: client
    });
  }

  async getRows(sheetName) {
    const client = await this.clientPromise;
    const response = await this.sheets.spreadsheets.values.get({
      spreadsheetId: this.spreadsheetId,
      range: `${sheetName}!A:F`,
      auth: client
    });

    const rows = response.data.values ?? [];
    const [header, ...dataRows] = rows;
    return { header, rows: dataRows };
  }
}
