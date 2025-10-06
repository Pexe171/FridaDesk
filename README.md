# CRM CCA

Sistema de CRM focado no atendimento automatizado via WhatsApp Web com registro das interações na planilha **Atendimentos CCA** e painel visual para controle de tarefas.

## Principais recursos

- **Integração com WhatsApp Web** através da biblioteca [`whatsapp-web.js`](https://github.com/pedroslopez/whatsapp-web.js).
- **Classificação automática** das mensagens recebidas com base em palavras-chave configuráveis.
- **Registro imediato** de cada atendimento como tarefa na aba `Atendimentos CCA` da planilha Google.
- **Controle de analistas** por meio da aba `Analistas`, incluindo disponibilidade e direcionamento automático de tarefas.
- **Painel web** em tempo real para acompanhar os atendimentos em aberto, organizados por categoria, com opção de concluir tarefas.
- **Notificações instantâneas** entre estações através de WebSockets, mantendo tarefas, analistas e configurações sincronizados sem recarregar a página.
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

1. (Opcional) Ajuste a porta HTTP criando um arquivo `.env` com a variável `PORT`. O valor padrão é `3000` e o arquivo `.env.example` traz esse único exemplo.
2. (Opcional) Defina a interface de rede usada pelo servidor HTTP com a variável `HOST`. O valor padrão é `0.0.0.0`, permitindo que outras máquinas da rede local acessem o painel utilizando o IP do computador host.
3. Instale as dependências:

   ```bash
   npm install
   ```

4. Inicie o servidor:

   ```bash
   npm run dev
   ```

- A API e o painel serão disponibilizados em `http://localhost:PORT` e também pelos endereços `http://IP_DA_MAQUINA:PORT` exibidos no terminal ao iniciar o servidor quando `HOST=0.0.0.0`.
  - Após configurar uma sessão no painel, o QR Code para pareamento fica disponível diretamente na interface web. Utilize o botão **Gerar novo QR Code** sempre que precisar renovar o pareamento.

5. Acesse `http://localhost:PORT/panel`, clique em **Configurações** na barra superior e informe os dados da estação:

   - Sessão do WhatsApp (um identificador por máquina/setor).
   - Nome do analista logado.
   - Credenciais do Google Sheets (opcionais) para sincronizar com a planilha oficial.

6. As configurações ficam salvas em `tmp/app-settings.json`. Sem credenciais válidas do Google, o sistema opera automaticamente em modo local (`tmp/local-sheet-<sessão>.json`).

7. Ao abrir o painel, cada estação estabelece automaticamente uma conexão WebSocket segura com `ws://localhost:PORT/ws` (ou `wss://` em produção) para receber atualizações em tempo real.

## Configurações pelo painel

O painel web concentra todas as informações da estação. No canto superior direito há o botão **Configurações**, que abre um painel lateral para editar:

- **Sessão do WhatsApp**: define o diretório de autenticação utilizado pelo `whatsapp-web.js` e o arquivo local de fallback.
- **Analista desta estação**: usado para atualizar o status na planilha de analistas e identificar quem assumiu o atendimento.
- **Credenciais do Google Sheets**: ao informar `ID da planilha`, e-mail e chave privada do service account, o sistema passa a sincronizar diretamente com a planilha oficial. A chave pode ser colada no formato original; o painel converte automaticamente as quebras de linha necessárias.
- **ID do projeto (opcional)**: somente para contas Google que exigem o `project_id` explícito.

O painel exibe o status atual da integração (modo local ou Google Sheets) e da sessão do WhatsApp, ajudando a verificar rapidamente se tudo está conectado.
 
Cartões de monitoramento adicionais mostram em tempo real se o WhatsApp está conectado, quantas mensagens foram registradas, o QR Code vigente para pareamento e quais estações estão conectadas ao servidor.

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
- Um painel de status na parte superior apresenta a saúde do servidor, a conectividade com o WhatsApp (incluindo total de mensagens recebidas) e o QR Code atualizado para pareamento sem precisar abrir o terminal.
- As tarefas e o status dos analistas são atualizados em tempo real via WebSocket. O botão **Atualizar agora** e o modo de atualização automática a cada 15 segundos permanecem disponíveis como fallback caso o canal em tempo real esteja indisponível.

## Execução em múltiplas máquinas

- Escolha uma máquina para ser o **host** do CRM e mantenha o servidor em execução nela. As demais estações devem acessar `http://IP_DO_HOST:PORT/panel` (o IP é informado no terminal do host).
- Defina uma sessão distinta para cada estação diretamente pelo painel de configurações.
- Informe o nome do analista local para que o status seja atualizado automaticamente na aba `Analistas`.
- Todas as estações podem compartilhar as mesmas credenciais do Google Sheets para manter a sincronização com a planilha oficial.
- Alterações realizadas em qualquer estação (novas tarefas, conclusão de atendimentos, mudanças nas configurações ou status dos analistas) são propagadas instantaneamente para todas as demais via WebSocket.

## Canal em tempo real

O servidor expõe um endpoint WebSocket em `/ws`. Após a autenticação inicial (não há credenciais adicionais), cada cliente recebe uma mensagem `init` com o snapshot atual de tarefas, analistas, configurações e status de execução. Atualizações subsequentes são enviadas nos seguintes formatos:

- `tasks`: disparado quando há criação, atualização ou sincronização completa de tarefas.
- `analysts`: reflete modificações no status ou lista de analistas.
- `settings`: confirma alterações persistidas nas configurações locais da estação.
- `status`: informa o estado em tempo real dos serviços (armazenamento ativo, sessão do WhatsApp, analista logado etc.).

Esse canal pode ser reutilizado por dashboards externos ou outras integrações internas para acompanhar o fluxo de atendimentos sem recorrer a polling.

## Scripts disponíveis

| Comando | Descrição |
| --- | --- |
| `npm run dev` | Inicia o servidor em modo desenvolvimento. |
| `npm start` | Inicia o servidor em modo produção. |

## Próximos passos

- Conectar webhooks/automação com outros sistemas internos (ex.: CRM corporativo).
- Adicionar autenticação no painel.

---

Projeto preparado para evoluir com os próximos passos do CRM CCA.
