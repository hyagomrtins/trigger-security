# ⚡ TRIGGER SECURITY — IDS/WAF Educacional

> Sistema educacional de detecção e bloqueio de ataques web em tempo real.  
> Desenvolvido com HTML/CSS/JS vanilla + Python 3 (Standard Library apenas — zero dependências externas).

---

## 📁 Estrutura do Projeto

```
trigger-security/
├── index.html      # Frontend — interface Liquid Glass (sem frameworks)
├── server.py       # Backend — IDS/WAF + servidor HTTP + alertas por e-mail
├── .env.example    # Template de configuração de e-mail
├── .gitignore      # Protege credenciais de commits acidentais
└── README.md
```

---

## 🚀 Instalação e Execução

**Pré-requisito único:** Python 3.6+ instalado.

### 1. Clone o repositório

```bash
git clone https://github.com/seu-usuario/trigger-security.git
cd trigger-security
```

### 2. Configure os e-mails de alertas

```bash
cp .env.example .env
```

Edite o `.env` com suas credenciais:

```env
TRIGGER_EMAIL_DESTINO=seu@email.com                  # E-mail pessoal — alertas resumidos
TRIGGER_EMAIL_LOG=triggersecurity.ids@gmail.com       # E-mail de LOG — dados detalhados
TRIGGER_EMAIL_ORIGEM=triggersecurity.ids@gmail.com    # Conta remetente
TRIGGER_EMAIL_SENHA=sua_app_password_aqui
```

> **Sistema Dual de E-mail:**
> - **EMAIL_DESTINO** (pessoal): recebe notificações resumidas de login e erro
> - **EMAIL_LOG**: recebe relatórios detalhados com IP, User-Agent, senha parcial, etc.

> **Como gerar a App Password do Gmail:**
> 1. Ative a [verificação em 2 etapas](https://myaccount.google.com/security) na conta remetente
> 2. Acesse [myaccount.google.com/apppasswords](https://myaccount.google.com/apppasswords)
> 3. Selecione **"Outro (nome personalizado)"** → nomeie como "Trigger Security"
> 4. Copie a senha de 16 caracteres gerada e cole em `TRIGGER_EMAIL_SENHA`

### 3. Inicie o servidor

```bash
python3 server.py
```

> **Windows:** use `python server.py`

O servidor sobe automaticamente na porta `8080` (ou `8081`/`8082` se ocupada).  
Acesse no browser: **http://localhost:8080**

### 4. Verifique o e-mail no terminal

Ao iniciar, o sistema testa a conexão SMTP e exibe o status:

```
[*] Testando conexao SMTP...
[*] E-mail   : OK — Autenticado com sucesso
[*] Pessoal  : altdohyago123@gmail.com            ← alertas resumidos
[*] LOG      : triggersecurity.ids@gmail.com       ← relatórios detalhados
[*] DB       : sqlite3 :memory: OK
```

> ⚠️ Se aparecer `FALHA`, o sistema ainda funciona normalmente — apenas os alertas por e-mail não serão enviados.

---

## 🔐 Credenciais de Teste

| E-mail | Senha |
|---|---|
| `teste@trigger.com.br` | `Pa$$w0rd` |
| `com@trigger.com.br` | `Pa$$w0rd` |
| `admin@trigger.com.br` | `Pa$$w0rd` |

---

## 🛡️ Ataques Detectados

| Ataque | Camada de Detecção | Comportamento |
|---|---|---|
| **SQL Injection** | JS (frontend) + Python (backend) | Bloqueia imediatamente, envia alerta por e-mail |
| **XSS** | JS + Python | Bloqueia, registra e envia alerta |
| **Brute Force** | Python | 5 tentativas em 60s → IP bloqueado 300s → alerta |
| **Error SQL Injection** | Python | Credenciais inválidas → classifica como tentativa de intrusão → envia alerta dual |
| **Scanner / Bot** | Python — User-Agent | Detecta sqlmap, nikto, hydra, burp, nmap etc. |
| **Path Traversal** | Python — URL | Detecta `../`, `/etc/`, `%2F..` |
| **Payload gigante** | Python | Rejeita requisições com body > 10 KB |

---

## 📧 Sistema Dual de E-mail

Todo login ou erro dispara **dois e-mails automaticamente**:

| Destino | Tipo | Conteúdo |
|---|---|---|
| **EMAIL_DESTINO** (pessoal) | Resumido | Horário, usuário, IP, status |
| **EMAIL_LOG** | Detalhado (HTML) | IP, User-Agent, rota, senha parcial, nº tentativas, análise completa |

### Eventos que disparam e-mail:

| Evento | Assunto (pessoal) | Assunto (LOG) |
|---|---|---|
| Login bem-sucedido | ✅ Login bem-sucedido — email | [LOG] ✅ Login bem-sucedido — email |
| Credenciais inválidas | ⚠️ Error SQL Injection — email | [LOG] ⚠️ Error SQL Injection — email |
| Ataque IDS detectado | ALERTA IDS — SQLI/XSS | ALERTA IDS — SQLI/XSS |
| Brute Force | ALERTA IDS — Brute Force | ALERTA IDS — Brute Force |

---

## 🧪 Como Testar

### SQL Injection — pelo browser

1. Acesse `http://localhost:8080`
2. No campo **E-MAIL**, digite: `admin@trigger.com.br`
3. No campo **SENHA**, cole: `' OR '1'='1`
4. Clique em **AUTENTICAR**
5. O JS detecta, exibe alerta na tela e notifica o backend via `/alert`

> **Dica:** Para testar SQLi no campo e-mail também, use o campo senha (não há validação de formato nele).

### SQL Injection — bypass do frontend (curl)

Testa a detecção diretamente no backend, pulando o JS:

```bash
curl -X POST http://localhost:8080/login \
  -H "Content-Type: application/json" \
  -d '{"email":"'\'' OR 1=1--","senha":"qualquer"}'
```

### XSS — pelo browser

No campo **SENHA**, cole: `<script>alert(1)</script>`

### Brute Force — via terminal

```bash
for i in {1..6}; do
  curl -X POST http://localhost:8080/login \
    -H "Content-Type: application/json" \
    -d '{"email":"teste@trigger.com.br","senha":"senhaerrada"}';
  echo "";
done
```

Na **5ª tentativa** o IP é bloqueado por 5 minutos e o alerta é enviado por e-mail.

### Scanner / Bot

```bash
curl -X POST http://localhost:8080/login \
  -H "Content-Type: application/json" \
  -H "User-Agent: sqlmap/1.7" \
  -d '{"email":"teste@trigger.com.br","senha":"Pa$$w0rd"}'
```

### Path Traversal

```bash
curl "http://localhost:8080/../etc/passwd"
```

---

## 🖥️ Logs no Terminal

| Cor | Evento |
|---|---|
| 🔴 Vermelho | Ataque detectado e bloqueado |
| 🟡 Amarelo | Comportamento suspeito / credenciais inválidas |
| 🟢 Verde | Login bem-sucedido / e-mail enviado com sucesso |
| 🔵 Azul | Requisição normal / status do servidor |

Exemplo de saída:

```
[2025-05-31 14:22:01] [IDS]    IP:127.0.0.1 | Rota:/login | SQL Injection detectado no campo 'email' | Status:403
[2025-05-31 14:22:01] [EMAIL]  Enviado para altdohyago123@gmail.com: ALERTA IDS — SQLI | Status:OK
[2025-05-31 14:22:05] [LOGIN]  IP:127.0.0.1 | Rota:/login | Error SQL Injection — credenciais invalidas: hacker@evil.com | Status:401
[2025-05-31 14:22:05] [EMAIL]  Enviado para altdohyago123@gmail.com: ⚠️ Error SQL Injection — hacker@evil.com | Status:OK
[2025-05-31 14:22:05] [EMAIL]  Enviado para triggersecurity.ids@gmail.com: [LOG] ⚠️ Error SQL Injection — hacker@evil.com | Status:OK
[2025-05-31 14:22:10] [LOGIN]  IP:127.0.0.1 | Rota:/login | Login bem-sucedido: admin@trigger.com.br | Status:200
[2025-05-31 14:22:10] [EMAIL]  Enviado para altdohyago123@gmail.com: ✅ Login bem-sucedido — admin@trigger.com.br | Status:OK
[2025-05-31 14:22:10] [EMAIL]  Enviado para triggersecurity.ids@gmail.com: [LOG] ✅ Login bem-sucedido — admin@trigger.com.br | Status:OK
```

---

## 🗺️ Rotas da API

| Método | Rota | Descrição |
|---|---|---|
| `GET` | `/` | Serve o `index.html` |
| `POST` | `/login` | Autenticação + IDS (SQLi, XSS, Brute Force) |
| `POST` | `/alert` | Recebe alertas detectados pelo frontend (JS) |

### Exemplos de Response

**Login bem-sucedido:**
```json
{ "status": "ok", "usuario": "admin@trigger.com.br" }
```

**Ataque detectado:**
```json
{ "status": "bloqueado", "motivo": "Ataque SQLI detectado e registrado" }
```

**IP bloqueado (brute force):**
```json
{ "status": "bloqueado", "motivo": "IP bloqueado por 300s após 5 tentativas falhas" }
```

---

## 🏗️ Arquitetura

```
Browser (index.html)
│
│  1. JS valida campos localmente (SQLi / XSS)
│  2. Ataque detectado → POST /alert → backend registra + envia e-mail
│  3. Campos limpos   → POST /login → backend autentica + IDS duplo
│
└──► server.py (Python 3, stdlib apenas)
      │
      ├── _anomalias()              Checagens globais: bloqueio, UA, traversal, payload
      ├── verificar_ids()           Regex SQLi + XSS nos campos do body JSON
      ├── registrar_tentativa()     Rate limiting por IP (sqlite3 :memory:)
      ├── testar_smtp()             Testa SMTP na inicialização — feedback imediato
      ├── enviar_email()            Thread daemon → envia para EMAIL_DESTINO
      ├── enviar_email_dual()       Envia para AMBOS (pessoal + LOG)
      └── _enviar_para()            Motor SMTP de baixo nível com retry
```

---

## ⚙️ Configurações

```python
# Brute Force (em server.py ou via .env)
LIMITE_TENTATIVAS = 5    # tentativas antes do bloqueio
JANELA_SEGUNDOS   = 60   # janela de contagem (segundos)
BLOQUEIO_SEGUNDOS = 300  # duração do bloqueio (5 minutos)

# Payload
MAX_CONTENT_LENGTH = 10240  # 10 KB máximo por requisição
```

---

## 🔒 Segurança do Repositório

Este projeto usa variáveis de ambiente para proteger credenciais:

- Credenciais ficam **somente no `.env`** (nunca no código)
- O `.gitignore` impede que o `.env` seja commitado acidentalmente
- O `.env.example` serve de template público sem dados sensíveis

```bash
# Verificar se .env está sendo ignorado corretamente
git status   # .env NÃO deve aparecer na lista
```

---

## ⚠️ Aviso de Uso

Este sistema é **estritamente educacional**.  
Destina-se ao aprendizado de conceitos de segurança ofensiva/defensiva em ambientes controlados.  
**Não utilize em produção** sem auditoria completa de segurança.

---

## 🧰 Tecnologias

- **Frontend:** HTML5 · CSS3 · JavaScript ES6 (vanilla, zero dependências)
- **Backend:** Python 3 · `http.server` · `sqlite3` · `smtplib` · `threading`
- **Fonte:** [Space Mono](https://fonts.google.com/specimen/Space+Mono) (Google Fonts)
- **Visual:** Liquid Glass Futurista — `#00e5ff` / `#f0f8ff` / `#000a14`

---

*TRIGGER SECURITY © 2025 — Sistema Educacional de Monitoramento de Acesso*
*Atualizado com Sistema Dual de E-mail — v2.0*
