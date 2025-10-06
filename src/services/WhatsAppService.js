import qrcode from 'qrcode-terminal';
import whatsapp from 'whatsapp-web.js';

const { Client, LocalAuth } = whatsapp;

export class WhatsAppService {
  constructor({ keywordClassifier, taskManager, analystManager, sessionId, localAnalystName }) {
    this.keywordClassifier = keywordClassifier;
    this.taskManager = taskManager;
    this.analystManager = analystManager;
    this.sessionId = sessionId || 'default';
    this.localAnalystName = localAnalystName;
    this.client = undefined;
  }

  async init() {
    if (this.client) {
      return;
    }
    this.client = new Client({
      authStrategy: new LocalAuth({ clientId: this.sessionId }),
      puppeteer: {
        args: ['--no-sandbox', '--disable-setuid-sandbox']
      }
    });

    this.client.on('qr', (qr) => {
      qrcode.generate(qr, { small: true });
      console.log('Escaneie o QR Code acima para conectar ao WhatsApp.');
    });

    this.client.on('ready', () => {
      console.log('Conectado ao WhatsApp com sucesso.');
    });

    this.client.on('message', async (message) => {
      try {
        await this.handleIncomingMessage(message);
      } catch (error) {
        console.error('Erro ao tratar mensagem recebida:', error);
      }
    });

    this.client.on('auth_failure', (msg) => {
      console.error('Falha de autenticação com o WhatsApp:', msg);
    });

    await this.client.initialize();
    console.log('Cliente do WhatsApp iniciado.');
  }

  async shutdown() {
    if (!this.client) {
      return;
    }
    try {
      await this.client.destroy();
      console.log('Cliente do WhatsApp finalizado.');
    } catch (error) {
      console.warn('Não foi possível encerrar o cliente do WhatsApp:', error);
    } finally {
      this.client = undefined;
    }
  }

  updateLocalAnalystName(name) {
    this.localAnalystName = name;
  }

  composeAutoReply({ category, analystName, keyword }) {
    if (!category) {
      return 'Recebemos sua mensagem e direcionamos o atendimento para a equipe responsável.';
    }

    if (analystName) {
      return `Olá! Identificamos que sua mensagem trata de ${category}. O analista ${analystName} continuará o atendimento em instantes.`;
    }

    if (keyword) {
      return `Obrigado por entrar em contato sobre ${category}. Nossa equipe já foi notificada e retornará em breve.`;
    }

    return 'Obrigado pelo contato! Encaminhamos sua solicitação para o setor responsável e retornaremos em breve.';
  }

  async handleIncomingMessage(message) {
    if (message.fromMe) {
      return;
    }
    const body = (message.body || '').trim();
    if (!body) {
      return;
    }

    await this.keywordClassifier.load();
    await this.analystManager.refreshAnalysts();

    const classification = this.keywordClassifier.classify(body);
    const preferredAnalyst = this.localAnalystName;
    const analyst = await this.analystManager.assignAnalyst(classification.category, preferredAnalyst);

    let analystName = '';
    if (analyst) {
      analystName = analyst.name;
    } else if (preferredAnalyst) {
      analystName = preferredAnalyst;
      try {
        await this.analystManager.updateAnalystStatus(preferredAnalyst, 'Ocupado');
      } catch (error) {
        console.warn('Não foi possível marcar analista local como ocupado:', error.message);
      }
    }

    const contact = await message.getContact();
    const number = contact.number || message.from;
    const keywordUsed = classification.keyword;

    const task = await this.taskManager.registerTask({
      number,
      category: classification.category,
      message: body,
      analyst: analystName
    });

    const reply = this.composeAutoReply({
      category: classification.category,
      analystName,
      keyword: keywordUsed
    });

    await message.reply(reply);
    console.log(`Mensagem registrada como tarefa #${task.id} - Categoria ${task.category}`);
  }
}
