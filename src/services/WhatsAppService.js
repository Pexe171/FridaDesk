import { EventEmitter } from 'events';
import qrcode from 'qrcode';
import whatsapp from 'whatsapp-web.js';

const { Client, LocalAuth } = whatsapp;

function now() {
  return Date.now();
}

export class WhatsAppService extends EventEmitter {
  constructor({ keywordClassifier, taskManager, analystManager, sessionId, localAnalystName }) {
    super();
    this.keywordClassifier = keywordClassifier;
    this.taskManager = taskManager;
    this.analystManager = analystManager;
    this.sessionId = sessionId || 'default';
    this.localAnalystName = localAnalystName;
    this.client = undefined;
    this.initializing = undefined;
    this.status = {
      session: this.sessionId,
      active: false,
      connected: false,
      initializing: false,
      qr: null,
      qrImage: null,
      qrGeneratedAt: null,
      readyAt: null,
      messageCount: 0,
      lastMessageAt: null,
      error: null
    };
  }

  async init() {
    if (this.initializing) {
      return this.initializing;
    }
    if (this.client) {
      return;
    }

    const initializeClient = async () => {
      this.client = new Client({
        authStrategy: new LocalAuth({ clientId: this.sessionId }),
        puppeteer: {
          args: ['--no-sandbox', '--disable-setuid-sandbox']
        }
      });

      this.client.on('qr', async (qr) => {
        try {
          const qrImage = await qrcode.toDataURL(qr, {
            errorCorrectionLevel: 'M',
            margin: 1,
            scale: 6
          });
          this.updateStatus({
            qr,
            qrImage,
            qrGeneratedAt: now(),
            connected: false,
            initializing: false,
            error: null
          });
        } catch (error) {
          console.warn('Não foi possível gerar QR Code para exibição no painel:', error.message);
          this.updateStatus({
            qr,
            qrImage: null,
            qrGeneratedAt: now(),
            connected: false,
            initializing: false,
            error: null
          });
        }
        console.log('QR Code disponível no painel para pareamento com WhatsApp.');
      });

      this.client.on('ready', () => {
        console.log('Conectado ao WhatsApp com sucesso.');
        this.updateStatus({
          connected: true,
          initializing: false,
          qr: null,
          qrImage: null,
          readyAt: now(),
          error: null
        });
      });

      this.client.on('disconnected', (reason) => {
        console.warn('Cliente WhatsApp desconectado:', reason);
        this.updateStatus({
          connected: false,
          initializing: false,
          error: { type: 'disconnected', message: reason }
        });
      });

      this.client.on('message', async (message) => {
        try {
          const processed = await this.handleIncomingMessage(message);
          if (processed) {
            this.updateStatus({
              messageCount: this.status.messageCount + 1,
              lastMessageAt: now()
            });
          }
        } catch (error) {
          console.error('Erro ao tratar mensagem recebida:', error);
        }
      });

      this.client.on('auth_failure', (msg) => {
        console.error('Falha de autenticação com o WhatsApp:', msg);
        this.updateStatus({
          connected: false,
          initializing: false,
          error: { type: 'auth_failure', message: msg }
        });
      });

      this.updateStatus({ active: true, initializing: true, connected: false, error: null });
      await this.client.initialize();
      console.log('Cliente do WhatsApp iniciado.');
    };

    this.initializing = initializeClient()
      .catch((error) => {
        console.error('Não foi possível iniciar o cliente WhatsApp:', error);
        this.updateStatus({
          active: false,
          connected: false,
          initializing: false,
          error: { type: 'startup', message: error.message }
        });
        throw error;
      })
      .finally(() => {
        this.initializing = undefined;
      });

    return this.initializing;
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
      this.updateStatus({
        active: false,
        connected: false,
        initializing: false
      });
    }
  }

  updateLocalAnalystName(name) {
    this.localAnalystName = name;
  }

  async resetSession() {
    if (!this.client) {
      throw new Error('Cliente WhatsApp não está inicializado.');
    }
    console.log('Reiniciando sessão do WhatsApp e aguardando novo QR Code.');
    try {
      await this.client.logout();
    } catch (error) {
      console.warn('Não foi possível efetuar logout da sessão atual:', error.message);
    }
    try {
      await this.client.destroy();
    } catch (error) {
      console.warn('Não foi possível destruir cliente atual durante reset:', error.message);
    }
    this.client = undefined;
    this.updateStatus({
      active: false,
      connected: false,
      initializing: false,
      qr: null,
      qrImage: null,
      qrGeneratedAt: null,
      readyAt: null,
      messageCount: 0,
      lastMessageAt: null,
      error: null
    });
    await this.init();
  }

  updateStatus(patch = {}) {
    this.status = {
      ...this.status,
      ...patch,
      session: this.sessionId
    };
    this.emit('status', this.getStatus());
  }

  getStatus() {
    return { ...this.status };
  }

  composeAutoReply({ category, analystName, keyword, suggestions = [] }) {
    const normalizedSuggestions = Array.isArray(suggestions)
      ? suggestions.filter((item, index, array) => item && array.indexOf(item) === index)
      : [];
    if (!category) {
      let fallback = 'Recebemos sua mensagem e direcionamos o atendimento para a equipe responsável.';
      if (normalizedSuggestions.length) {
        fallback += `\n\nPortas de atendimento disponíveis:\n${normalizedSuggestions
          .slice(0, 4)
          .map((name, index) => `${index + 1}. ${name}`)
          .join('\n')}`;
        fallback += '\n\nBasta responder com a palavra-chave correspondente para seguirmos com o suporte.';
      }
      return fallback;
    }

    let message;
    if (analystName) {
      message = `Olá! Identificamos que sua mensagem trata de ${category}. O analista ${analystName} continuará o atendimento em instantes.`;
    } else if (keyword) {
      message = `Obrigado por entrar em contato sobre ${category}. Nossa equipe já foi notificada e retornará em breve.`;
    } else {
      message = 'Obrigado pelo contato! Encaminhamos sua solicitação para o setor responsável e retornaremos em breve.';
    }

    if (normalizedSuggestions.length) {
      message += `\n\nPortas de atendimento disponíveis:\n${normalizedSuggestions
        .slice(0, 4)
        .map((name, index) => `${index + 1}. ${name}`)
        .join('\n')}`;
      message += '\n\nResponda com a opção desejada ou envie a palavra-chave correspondente.';
    }
    return message;
  }

  async handleIncomingMessage(message) {
    if (message.fromMe) {
      return false;
    }
    if (message.isStatus) {
      return false;
    }
    if (typeof message.from === 'string' && message.from.endsWith('@g.us')) {
      console.log('Mensagem recebida em grupo ignorada.', message.from);
      return false;
    }
    const body = (message.body || '').trim();
    if (!body) {
      return false;
    }

    await this.keywordClassifier.load();
    await this.analystManager.refreshAnalysts();

    const classification = this.keywordClassifier.classify(body);
    const availableCategories = this.keywordClassifier
      .listCategories()
      .map((category) => category.name)
      .filter(Boolean);
    if (this.keywordClassifier.defaultCategory) {
      availableCategories.push(this.keywordClassifier.defaultCategory);
    }
    const suggestions = availableCategories
      .filter((name) => name !== classification.category)
      .filter((name, index, array) => array.indexOf(name) === index)
      .slice(0, 4);
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
      keyword: keywordUsed,
      suggestions
    });

    await message.reply(reply);
    console.log(`Mensagem registrada como tarefa #${task.id} - Categoria ${task.category}`);
    return true;
  }
}
