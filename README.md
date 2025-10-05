# CRM CCA

Sistema de CRM focado no atendimento automatizado via WhatsApp Web com registro das interações na planilha **Atendimentos CCA** e painel visual para controle de tarefas.

## Principais recursos

- **Integração com WhatsApp Web** através da biblioteca [`whatsapp-web.js`](https://github.com/pedroslopez/whatsapp-web.js).
- **Classificação automática** das mensagens recebidas com base em palavras-chave configuráveis.
- **Registro imediato** de cada atendimento como tarefa na aba `Atendimentos CCA` da planilha Google.
- **Controle de analistas** por meio da aba `Analistas`, incluindo disponibilidade e direcionamento automático de tarefas.
- **Painel web** em tempo real para acompanhar os atendimentos em aberto, organizados por categoria, com opção de concluir tarefas.
- **Atualização dinâmica de palavras-chave** sem alterar o código principal (via API ou edição do arquivo `src/config/keywords.json`).
- **Modo offline** para desenvolvimento local usando armazenamento em arquivo (`tmp/local-sheet-*.json`) quando as credenciais do Google não estiverem configuradas.

## Estrutura de pastas

```
.
├── .env.example
├── package.json
├── src
│   ├── config
│   │   └── keywords.json
│   ├── index.js
│   ├── panel
│   │   ├── app.js
│   │   ├── index.html
│   │   └── style.css
│   ├── server
│   │   └── httpServer.js
│   └── services
│       ├── AnalystManager.js
│       ├── GoogleSheetsService.js
│       ├── KeywordClassifier.js
│       ├── LocalSheetsService.js
│       ├── TaskManager.js
│       └── WhatsAppService.js
└── tmp
```

## Preparação do ambiente

1. Copie o arquivo `.env.example` para `.env` e preencha as variáveis:

   ```bash
   cp .env.example .env
   ```

   | Variável | Descrição |
   | --- | --- |
   | `PORT` | Porta HTTP da API/painel (padrão 3000). |
   | `WHATSAPP_SESSION` | Identificador da sessão do WhatsApp (um por máquina/setor). |
   | `ANALYST_NAME` | Nome do analista logado na estação. |
   | `GOOGLE_SHEET_ID` | ID da planilha `Atendimentos CCA` no Google Sheets. |
   | `GOOGLE_CLIENT_EMAIL` | E-mail do service account Google. |
   | `GOOGLE_PRIVATE_KEY` | Chave privada do service account (com `\n` para quebras de linha). |
   | `GOOGLE_PROJECT_ID` | Opcional, ID do projeto Google Cloud. |

   > Caso as credenciais do Google não sejam fornecidas, o sistema utilizará automaticamente um arquivo local (`tmp/local-sheet-{sessão}.json`) para simular a planilha durante o desenvolvimento.

2. Instale as dependências:

   ```bash
   npm install
   ```

3. Inicie o servidor:

   ```bash
   npm run dev
   ```

   - A API e o painel serão disponibilizados em `http://localhost:PORT`.
   - A primeira execução exibirá um QR Code no terminal. Escaneie com o WhatsApp do setor correspondente.

## Planilha Google

Crie uma planilha chamada **Atendimentos CCA** com duas abas:

1. **Atendimentos CCA**

   | Data | Número | Categoria | Mensagem | Status | Analista |
   | --- | --- | --- | --- | --- | --- |

2. **Analistas**

   | Nome | Categoria | Status |
   | --- | --- | --- |

Certifique-se de compartilhar a planilha com o e-mail do service account configurado.

## Fluxo de atendimento

1. O cliente envia mensagem via WhatsApp.
2. O sistema classifica automaticamente o conteúdo usando o arquivo `keywords.json`.
3. O `AnalystManager` verifica a aba `Analistas` para encontrar um profissional disponível para a categoria.
4. Uma tarefa é registrada na aba `Atendimentos CCA` com status **Aberto** e o analista designado.
5. O cliente recebe resposta automática informando que o atendimento foi direcionado ao setor correto.
6. Pelo painel (`/panel`), os analistas acompanham os atendimentos em aberto e podem concluir o atendimento com um clique.
7. Ao concluir, o status é atualizado para **Concluído** na planilha e o analista volta a ficar **Disponível**.

## Adicionando novas palavras-chave

Você pode atualizar as categorias de duas maneiras:

1. **Editando o arquivo** `src/config/keywords.json` e reiniciando o servidor.
2. **Via API**: enviar um POST para `/api/keywords` com o corpo:

   ```json
   {
     "category": "Financiamento",
     "keywords": ["financiamento", "financiar"],
     "color": "#4C1D95"
   }
   ```

As alterações são persistidas no arquivo JSON, garantindo que futuras execuções reconheçam os novos termos.

## Painel de atendimento

- Acesse `http://localhost:PORT/panel`.
- Cada categoria possui uma coluna com cor distinta.
- Botões **Concluir atendimento** atualizam o status diretamente na planilha.
- A lista é atualizada automaticamente a cada 15 segundos ou manualmente pelo botão **Atualizar agora**.

## Execução em múltiplas máquinas

- Configure `WHATSAPP_SESSION` com um identificador único para cada computador/linha de atendimento.
- Defina `ANALYST_NAME` com o nome do analista responsável pela estação. O sistema atualiza automaticamente o status na planilha.
- Todos os ambientes compartilham a mesma planilha do Google e, consequentemente, o mesmo painel atualizado em tempo real.

## Scripts disponíveis

| Comando | Descrição |
| --- | --- |
| `npm run dev` | Inicia o servidor em modo desenvolvimento. |
| `npm start` | Inicia o servidor em modo produção. |

## Próximos passos

- Conectar webhooks/automação com outros sistemas internos (ex.: CRM corporativo).
- Adicionar autenticação no painel.
- Criar notificações em tempo real (WebSocket) para atualização instantânea entre estações.

---

Projeto preparado para evoluir com os próximos passos do CRM CCA.
