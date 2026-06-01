#!/usr/bin/env python3
"""TRIGGER SECURITY — IDS/WAF Backend"""
import http.server
import json
import re
import sqlite3
import threading
import time
import socket
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from urllib.parse import unquote
# Configuração de e-mail
EMAIL_DESTINO = "altdohyago123@gmail.com"       # E-mail pessoal — recebe alertas resumidos
EMAIL_LOG     = "triggersecurity.ids@gmail.com"  # E-mail de LOG — recebe dados detalhados
EMAIL_ORIGEM  = "triggersecurity.ids@gmail.com"  # Conta Gmail remetente
EMAIL_SENHA   = "lqsygzgwhbzilqxf"              # App Password sem espaços — obrigatório
SMTP_HOST     = "smtp.gmail.com"
SMTP_PORT     = 587
# Credenciais
CREDENCIAIS = {
    "teste@trigger.com.br": "Pa$$w0rd",
    "com@trigger.com.br": "Pa$$w0rd",
    "admin@trigger.com.br": "Pa$$w0rd",
}
# Rate limiting
LIMITE_TENTATIVAS = 5
JANELA_SEGUNDOS = 60
BLOQUEIO_SEGUNDOS = 300
# Padrões IDS
PADRAO_SQLI = re.compile(
    r"('|--|/\*|\*/|union|select|drop|insert|delete|or\s+1\s*=\s*1"
    r"|;\s*drop|exec\s*\(|cast\s*\(|char\s*\(|xp_|0x[0-9a-f]+|%27|%20or%20)",
    re.IGNORECASE,
)
PADRAO_XSS = re.compile(
    r"(<script|javascript:|onerror\s*=|onload\s*=|<img|alert\s*\(|<svg|<iframe)",
    re.IGNORECASE,
)
PADRAO_PATH_TRAVERSAL = re.compile(r"(\.\./|\.\.%2[fF]|/etc/|/proc/)")
PADRAO_SCANNER = re.compile(
    r"(sqlmap|nikto|masscan|nmap|dirbuster|burp|hydra|w3af|python-requests|curl)",
    re.IGNORECASE,
)
MAX_CONTENT_LENGTH = 10240
# Cores ANSI
AZ = "\033[94m"
VD = "\033[92m"
AM = "\033[93m"
VM = "\033[91m"
CI = "\033[96m"
RS = "\033[0m"
# Banco em memória — thread-safe
db_lock = threading.Lock()
db = sqlite3.connect(":memory:", check_same_thread=False)
db.execute("CREATE TABLE tentativas(ip TEXT, ts REAL)")
db.execute("CREATE TABLE bloqueios(ip TEXT, ate REAL)")
db.commit()
def agora():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")
def log(cor, tipo, ip, rota, motivo, codigo):
    print(f"{cor}[{agora()}] [{tipo}] IP:{ip} | Rota:{rota} | {motivo} | Status:{codigo}{RS}")
def email_configurado():
    return EMAIL_SENHA not in ("SUA_APP_PASSWORD_GMAIL", "", "xxxx xxxx xxxx xxxx")
def _conectar_smtp():
    """Abre conexao SMTP autenticada. Lanca excecao em caso de falha."""
    ip_smtp = socket.getaddrinfo(SMTP_HOST, SMTP_PORT, socket.AF_INET)[0][4][0]
    srv = smtplib.SMTP(ip_smtp, SMTP_PORT, timeout=20)
    srv.ehlo()
    srv.starttls()
    srv.ehlo()
    srv.login(EMAIL_ORIGEM, EMAIL_SENHA)
    return srv
def testar_smtp():
    """
    Testa a conexao SMTP na inicializacao do servidor.
    Retorna (True, "") em sucesso ou (False, motivo) em falha.
    """
    if not email_configurado():
        return False, "App Password nao configurada"
    try:
        srv = _conectar_smtp()
        srv.quit()
        return True, ""
    except smtplib.SMTPAuthenticationError:
        return False, (
            "AUTENTICACAO FALHOU — App Password invalida ou revogada.\n"
            "    Acesse: https://myaccount.google.com/apppasswords\n"
            "    Gere uma nova senha e atualize EMAIL_SENHA no server.py"
        )
    except Exception as ex:
        return False, f"Erro de conexao SMTP: {ex}"
# =====================================================================
#  SISTEMA DUAL DE E-MAIL
#  - EMAIL_DESTINO (pessoal): recebe alertas resumidos
#  - EMAIL_LOG: recebe dados técnicos detalhados para análise forense
# =====================================================================
def _enviar_para(destinatario, assunto, corpo_texto, corpo_html=None):
    """Envia um e-mail para um destinatário específico (uso interno)."""
    if not email_configurado():
        return
    def _enviar():
        for tentativa in range(3):
            try:
                if corpo_html:
                    msg = MIMEMultipart("alternative")
                    msg.attach(MIMEText(corpo_texto, "plain", "utf-8"))
                    msg.attach(MIMEText(corpo_html, "html", "utf-8"))
                else:
                    msg = MIMEText(corpo_texto, "plain", "utf-8")
                msg["Subject"] = assunto
                msg["From"] = EMAIL_ORIGEM
                msg["To"] = destinatario
                with _conectar_smtp() as srv:
                    srv.sendmail(EMAIL_ORIGEM, destinatario, msg.as_string())
                log(VD, "EMAIL", "-", "-", f"Enviado para {destinatario}: {assunto}", "OK")
                return
            except smtplib.SMTPAuthenticationError as ex:
                log(VM, "EMAIL", "-", "-",
                    f"AUTENTICACAO FALHOU — App Password invalida ou revogada: {ex}", "ERRO")
                log(VM, "EMAIL", "-", "-",
                    "Acesse https://myaccount.google.com/apppasswords e gere nova senha", "-")
                return  # Nao adianta tentar novamente
            except Exception as ex:
                log(AM, "EMAIL", "-", "-", f"Falha tentativa {tentativa+1}/3 para {destinatario}: {ex}", "-")
                if tentativa < 2:
                    time.sleep(5)
        log(VM, "EMAIL", "-", "-", f"Todas as tentativas de envio para {destinatario} falharam", "ERRO")
    threading.Thread(target=_enviar, daemon=True).start()

def enviar_email(assunto, corpo):
    """Compatibilidade — envia para EMAIL_DESTINO (pessoal) com alerta resumido."""
    _enviar_para(EMAIL_DESTINO, assunto, corpo)

def enviar_email_dual(assunto, corpo_resumido, corpo_detalhado, corpo_detalhado_html=None):
    """
    Envia email para AMBOS os destinos:
    - EMAIL_DESTINO (pessoal): corpo resumido
    - EMAIL_LOG: corpo detalhado (com HTML opcional para melhor formatação)
    Usar SOMENTE quando o email do usuário é cadastrado.
    """
    _enviar_para(EMAIL_DESTINO, assunto, corpo_resumido)
    _enviar_para(EMAIL_LOG, f"[LOG] {assunto}", corpo_detalhado, corpo_detalhado_html)

def enviar_somente_log(assunto, corpo_texto, corpo_html=None):
    """
    Envia email SOMENTE para EMAIL_LOG.
    Usar quando o email inserido NÃO é cadastrado ou não há contexto de usuário.
    """
    _enviar_para(EMAIL_LOG, f"[LOG] {assunto}", corpo_texto, corpo_html)

def montar_corpo_alerta(ip, rota, tipo, payload, ua):
    return (
        "ALERTA — TRIGGER SECURITY IDS\n"
        "==============================\n"
        f"Timestamp  : {agora()}\n"
        f"IP         : {ip}\n"
        f"Rota       : {rota}\n"
        f"Tipo       : {tipo}\n"
        f"Payload    : {payload[:200]}\n"
        f"User-Agent : {ua}\n"
        "Status     : BLOQUEADO\n"
    )

def montar_corpo_login_resumido(ip, email_usuario, status):
    """Corpo resumido para o email pessoal (EMAIL_DESTINO)."""
    icone = "✅" if status == "sucesso" else "⚠️"
    tipo_evento = "Login bem-sucedido" if status == "sucesso" else "Error SQL Injection"
    return (
        f"{icone} TRIGGER SECURITY — {tipo_evento}\n"
        f"{'=' * 45}\n"
        f"Horário : {agora()}\n"
        f"Usuário : {email_usuario}\n"
        f"IP      : {ip}\n"
        f"Status  : {tipo_evento}\n"
    )

def montar_corpo_login_detalhado(ip, rota, email_usuario, senha_tentada, ua, status, tentativas=0):
    """Corpo detalhado para o email de LOG (EMAIL_LOG) — texto."""
    tipo_evento = "LOGIN BEM-SUCEDIDO" if status == "sucesso" else "ERROR SQL INJECTION"
    severidade = "INFO" if status == "sucesso" else "WARNING"
    senha_mascarada = senha_tentada[:2] + "*" * (len(senha_tentada) - 2) if len(senha_tentada) > 2 else "***"
    email_existe = "SIM" if email_usuario in CREDENCIAIS else "NAO"
    return (
        f"{'=' * 60}\n"
        f"  TRIGGER SECURITY — RELATÓRIO DETALHADO DE ACESSO\n"
        f"{'=' * 60}\n"
        f"\n"
        f"[EVENTO]       : {tipo_evento}\n"
        f"[SEVERIDADE]   : {severidade}\n"
        f"[TIMESTAMP]    : {agora()}\n"
        f"\n"
        f"--- DADOS DO ACESSO ---\n"
        f"E-mail         : {email_usuario}\n"
        f"Senha (parcial): {senha_mascarada}\n"
        f"Email existe?  : {email_existe}\n"
        f"\n"
        f"--- DADOS DE REDE ---\n"
        f"IP             : {ip}\n"
        f"Rota           : {rota}\n"
        f"User-Agent     : {ua}\n"
        f"\n"
        f"--- ANÁLISE ---\n"
        f"Tipo           : {tipo_evento}\n"
        f"Tentativas IP  : {tentativas}\n"
        f"Ação tomada    : {'Acesso concedido' if status == 'sucesso' else 'Acesso negado — credenciais inválidas'}\n"
        f"\n"
        f"{'=' * 60}\n"
        f"  Gerado automaticamente por TRIGGER SECURITY IDS/WAF\n"
        f"{'=' * 60}\n"
    )

def montar_corpo_login_detalhado_html(ip, rota, email_usuario, senha_tentada, ua, status, tentativas=0):
    """Corpo detalhado HTML para o email de LOG — formatação rica."""
    tipo_evento = "LOGIN BEM-SUCEDIDO" if status == "sucesso" else "ERROR SQL INJECTION"
    severidade = "INFO" if status == "sucesso" else "WARNING"
    cor_badge = "#00ff88" if status == "sucesso" else "#ff2255"
    cor_fundo_badge = "rgba(0,255,136,0.15)" if status == "sucesso" else "rgba(255,34,85,0.15)"
    senha_mascarada = senha_tentada[:2] + "*" * (len(senha_tentada) - 2) if len(senha_tentada) > 2 else "***"
    email_existe = "SIM" if email_usuario in CREDENCIAIS else "NÃO"
    return f"""<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#0a0e17;font-family:'Courier New',monospace;">
<div style="max-width:600px;margin:20px auto;background:#0d1117;border:1px solid #1a2332;border-radius:8px;overflow:hidden;">
  <div style="background:linear-gradient(135deg,#00e5ff,#0088cc);padding:20px 24px;">
    <h1 style="margin:0;font-size:18px;color:#000a14;letter-spacing:3px;">⚡ TRIGGER SECURITY</h1>
    <p style="margin:4px 0 0;font-size:12px;color:#001a2c;">RELATÓRIO DETALHADO DE ACESSO</p>
  </div>
  <div style="padding:24px;">
    <div style="display:inline-block;padding:4px 12px;border-radius:4px;font-size:12px;font-weight:bold;color:{cor_badge};background:{cor_fundo_badge};border:1px solid {cor_badge};margin-bottom:16px;">
      {tipo_evento}
    </div>
    <table style="width:100%;border-collapse:collapse;margin:16px 0;">
      <tr><td style="padding:8px 12px;color:#6a7a8a;font-size:12px;border-bottom:1px solid #1a2332;">Severidade</td>
          <td style="padding:8px 12px;color:#f0f8ff;font-size:12px;border-bottom:1px solid #1a2332;font-weight:bold;">{severidade}</td></tr>
      <tr><td style="padding:8px 12px;color:#6a7a8a;font-size:12px;border-bottom:1px solid #1a2332;">Timestamp</td>
          <td style="padding:8px 12px;color:#f0f8ff;font-size:12px;border-bottom:1px solid #1a2332;">{agora()}</td></tr>
      <tr><td style="padding:8px 12px;color:#6a7a8a;font-size:12px;border-bottom:1px solid #1a2332;">E-mail</td>
          <td style="padding:8px 12px;color:#00e5ff;font-size:12px;border-bottom:1px solid #1a2332;font-weight:bold;">{email_usuario}</td></tr>
      <tr><td style="padding:8px 12px;color:#6a7a8a;font-size:12px;border-bottom:1px solid #1a2332;">Senha (parcial)</td>
          <td style="padding:8px 12px;color:#f0f8ff;font-size:12px;border-bottom:1px solid #1a2332;">{senha_mascarada}</td></tr>
      <tr><td style="padding:8px 12px;color:#6a7a8a;font-size:12px;border-bottom:1px solid #1a2332;">Email cadastrado?</td>
          <td style="padding:8px 12px;color:{'#00ff88' if email_existe == 'SIM' else '#ff2255'};font-size:12px;border-bottom:1px solid #1a2332;font-weight:bold;">{email_existe}</td></tr>
      <tr><td style="padding:8px 12px;color:#6a7a8a;font-size:12px;border-bottom:1px solid #1a2332;">IP</td>
          <td style="padding:8px 12px;color:#f0f8ff;font-size:12px;border-bottom:1px solid #1a2332;">{ip}</td></tr>
      <tr><td style="padding:8px 12px;color:#6a7a8a;font-size:12px;border-bottom:1px solid #1a2332;">Rota</td>
          <td style="padding:8px 12px;color:#f0f8ff;font-size:12px;border-bottom:1px solid #1a2332;">{rota}</td></tr>
      <tr><td style="padding:8px 12px;color:#6a7a8a;font-size:12px;border-bottom:1px solid #1a2332;">User-Agent</td>
          <td style="padding:8px 12px;color:#f0f8ff;font-size:12px;border-bottom:1px solid #1a2332;word-break:break-all;">{ua}</td></tr>
      <tr><td style="padding:8px 12px;color:#6a7a8a;font-size:12px;border-bottom:1px solid #1a2332;">Tentativas do IP</td>
          <td style="padding:8px 12px;color:#f0f8ff;font-size:12px;border-bottom:1px solid #1a2332;">{tentativas}</td></tr>
      <tr><td style="padding:8px 12px;color:#6a7a8a;font-size:12px;">Ação</td>
          <td style="padding:8px 12px;color:{'#00ff88' if status == 'sucesso' else '#ff2255'};font-size:12px;font-weight:bold;">{'Acesso concedido' if status == 'sucesso' else 'Acesso negado — credenciais inválidas'}</td></tr>
    </table>
  </div>
  <div style="padding:12px 24px;background:#080c14;border-top:1px solid #1a2332;text-align:center;">
    <p style="margin:0;font-size:10px;color:#4a5a6a;letter-spacing:2px;">TRIGGER SECURITY IDS/WAF — GERADO AUTOMATICAMENTE</p>
  </div>
</div>
</body>
</html>"""

def verificar_bloqueio(ip):
    with db_lock:
        row = db.execute("SELECT ate FROM bloqueios WHERE ip=? AND ate>?", (ip, time.time())).fetchone()
    return row is not None
def registrar_tentativa(ip):
    agora_ts = time.time()
    with db_lock:
        # Limpa tentativas fora da janela
        db.execute("DELETE FROM tentativas WHERE ts<?", (agora_ts - JANELA_SEGUNDOS,))
        # Conta tentativas atuais ANTES de inserir a nova
        count = db.execute(
            "SELECT COUNT(*) FROM tentativas WHERE ip=? AND ts>?",
            (ip, agora_ts - JANELA_SEGUNDOS),
        ).fetchone()[0]
        # Insere a tentativa atual
        db.execute("INSERT INTO tentativas VALUES(?,?)", (ip, agora_ts))
        db.commit()
    # count ja tem as tentativas anteriores; +1 (a atual) = total real
    if count + 1 >= LIMITE_TENTATIVAS:
        with db_lock:
            # Evita duplicar bloqueio se ja houver registro ativo
            ativo = db.execute(
                "SELECT 1 FROM bloqueios WHERE ip=? AND ate>?", (ip, agora_ts)
            ).fetchone()
            if not ativo:
                db.execute("INSERT INTO bloqueios VALUES(?,?)", (ip, agora_ts + BLOQUEIO_SEGUNDOS))
                db.commit()
        return True, count + 1
    return False, count + 1

def contar_tentativas(ip):
    """Retorna o número de tentativas falhas do IP na janela atual."""
    agora_ts = time.time()
    with db_lock:
        count = db.execute(
            "SELECT COUNT(*) FROM tentativas WHERE ip=? AND ts>?",
            (ip, agora_ts - JANELA_SEGUNDOS),
        ).fetchone()[0]
    return count

def verificar_ids(campos, ip, rota, ua):
    for chave, valor in campos.items():
        if PADRAO_SQLI.search(str(valor)):
            return "sqli", f"SQL Injection detectado no campo '{chave}'"
        if PADRAO_XSS.search(str(valor)):
            return "xss", f"XSS detectado no campo '{chave}'"
    return None, None
class TriggerHandler(http.server.BaseHTTPRequestHandler):
    """Handler HTTP principal"""
    def log_message(self, fmt, *args):
        pass  # Suprime logs padrão do BaseHTTPRequestHandler
    def _ip(self):
        return self.client_address[0]
    def _ua(self):
        return self.headers.get("User-Agent", "")
    def _cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
    def _json_resp(self, code, obj):
        corpo = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self._cors()
        self.end_headers()
        self.wfile.write(corpo)
    def _anomalias(self):
        ip = self._ip()
        ua = self._ua()
        rota = self.path
        # Bloqueio ativo
        if verificar_bloqueio(ip):
            log(VM, "BLOQUEIO", ip, rota, "IP bloqueado por rate limiting", 429)
            self._json_resp(429, {"status": "bloqueado", "motivo": "IP bloqueado temporariamente por excesso de tentativas"})
            return True
        # Sem User-Agent
        if not ua:
            log(AM, "ANOMALIA", ip, rota, "Requisicao sem User-Agent", 400)
            self._json_resp(400, {"status": "erro", "motivo": "User-Agent ausente"})
            return True
        # Scanner conhecido — sem contexto de usuário → só LOG
        if PADRAO_SCANNER.search(ua):
            log(VM, "SCANNER", ip, rota, f"Scanner detectado: {ua[:80]}", 403)
            corpo = montar_corpo_alerta(ip, rota, "Scanner detectado", ua, ua)
            enviar_somente_log("ALERTA IDS — Scanner detectado", corpo)
            self._json_resp(403, {"status": "bloqueado", "motivo": "Ferramenta automatizada detectada"})
            return True
        # Path traversal — sem contexto de usuário → só LOG
        if PADRAO_PATH_TRAVERSAL.search(unquote(rota)):
            log(VM, "TRAVERSAL", ip, rota, "Path traversal detectado", 403)
            corpo = montar_corpo_alerta(ip, rota, "Path Traversal", rota, ua)
            enviar_somente_log("ALERTA IDS — Path Traversal", corpo)
            self._json_resp(403, {"status": "bloqueado", "motivo": "Path traversal detectado"})
            return True
        # Content-Length excessivo
        cl = self.headers.get("Content-Length", "0")
        try:
            if int(cl) > MAX_CONTENT_LENGTH:
                log(AM, "PAYLOAD", ip, rota, f"Content-Length excessivo: {cl}", 413)
                self._json_resp(413, {"status": "erro", "motivo": "Payload muito grande"})
                return True
        except ValueError:
            pass
        return False
    def _ler_json(self):
        cl = int(self.headers.get("Content-Length", 0))
        if cl == 0:
            return None
        raw = self.rfile.read(cl)
        return json.loads(raw.decode("utf-8"))
    def do_OPTIONS(self):
        self.send_response(204)
        self._cors()
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.end_headers()
    def do_GET(self):
        try:
            if self._anomalias():
                return
            if self.path == "/" or self.path == "/index.html":
                import os
                caminho = os.path.join(os.path.dirname(os.path.abspath(__file__)), "index.html")
                with open(caminho, "rb") as f:
                    conteudo = f.read()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self._cors()
                self.end_headers()
                self.wfile.write(conteudo)
                log(AZ, "GET", self._ip(), self.path, "Pagina servida", 200)
            else:
                self._json_resp(404, {"erro": "rota nao encontrada"})
                log(AM, "GET", self._ip(), self.path, "Rota inexistente", 404)
        except Exception as ex:
            log(VM, "ERRO", self._ip(), self.path, str(ex), 500)
            self._json_resp(500, {"status": "erro", "motivo": "Erro interno do servidor"})
    def do_POST(self):
        ip = self._ip()
        ua = self._ua()
        rota = self.path
        try:
            if self._anomalias():
                return
            # Ler JSON
            try:
                dados = self._ler_json()
            except (json.JSONDecodeError, UnicodeDecodeError):
                log(AM, "PARSE", ip, rota, "JSON malformado", 400)
                self._json_resp(400, {"status": "erro", "motivo": "JSON malformado"})
                return
            if dados is None:
                log(AM, "PARSE", ip, rota, "Body vazio", 400)
                self._json_resp(400, {"status": "erro", "motivo": "Body vazio"})
                return
            # Rota /login
            if rota == "/login":
                email = dados.get("email")
                senha = dados.get("senha")
                if not email or not senha:
                    log(AM, "LOGIN", ip, rota, "Campos ausentes", 400)
                    self._json_resp(400, {"status": "erro", "motivo": "Campos email e senha sao obrigatorios"})
                    return
                # IDS nos campos
                tipo_ataque, descr = verificar_ids(dados, ip, rota, ua)
                if tipo_ataque:
                    log(VM, "IDS", ip, rota, descr, 403)
                    payload_str = json.dumps(dados, ensure_ascii=False)
                    corpo = montar_corpo_alerta(ip, rota, tipo_ataque.upper(), payload_str, ua)
                    # Email cadastrado → dual | Não cadastrado → só LOG
                    if email in CREDENCIAIS:
                        enviar_email_dual(
                            f"ALERTA IDS — {tipo_ataque.upper()}",
                            corpo, corpo
                        )
                    else:
                        enviar_somente_log(f"ALERTA IDS — {tipo_ataque.upper()}", corpo)
                    self._json_resp(403, {"status": "bloqueado", "motivo": f"Ataque {tipo_ataque.upper()} detectado e registrado"})
                    return
                # Verificar credenciais
                if CREDENCIAIS.get(email) == senha:
                    # ===== LOGIN BEM-SUCEDIDO — envio dual =====
                    log(VD, "LOGIN", ip, rota, f"Login bem-sucedido: {email}", 200)
                    corpo_resumido = montar_corpo_login_resumido(ip, email, "sucesso")
                    corpo_detalhado = montar_corpo_login_detalhado(
                        ip, rota, email, senha, ua, "sucesso", tentativas=0
                    )
                    corpo_html = montar_corpo_login_detalhado_html(
                        ip, rota, email, senha, ua, "sucesso", tentativas=0
                    )
                    enviar_email_dual(
                        f"✅ Login bem-sucedido — {email}",
                        corpo_resumido, corpo_detalhado, corpo_html
                    )
                    self._json_resp(200, {"status": "ok", "usuario": email})
                else:
                    # ===== CREDENCIAIS INVÁLIDAS — Error SQL Injection =====
                    bloqueado, total_tentativas = registrar_tentativa(ip)
                    email_cadastrado = email in CREDENCIAIS  # email existe mas senha errada?
                    if bloqueado:
                        log(VM, "BRUTE", ip, rota, f"Rate limit atingido apos falha: {email}", 429)
                        corpo = montar_corpo_alerta(ip, rota, "Brute Force", email, ua)
                        # Email cadastrado → dual | Não cadastrado → só LOG
                        if email_cadastrado:
                            enviar_email_dual(
                                "ALERTA IDS — Brute Force",
                                corpo, corpo
                            )
                        else:
                            enviar_somente_log("ALERTA IDS — Brute Force", corpo)
                        self._json_resp(429, {"status": "bloqueado", "motivo": f"IP bloqueado por {BLOQUEIO_SEGUNDOS}s apos {LIMITE_TENTATIVAS} tentativas falhas"})
                    else:
                        log(AM, "LOGIN", ip, rota, f"Error SQL Injection — credenciais invalidas: {email}", 401)
                        corpo_resumido = montar_corpo_login_resumido(ip, email, "erro")
                        corpo_detalhado = montar_corpo_login_detalhado(
                            ip, rota, email, senha, ua, "erro", tentativas=total_tentativas
                        )
                        corpo_html = montar_corpo_login_detalhado_html(
                            ip, rota, email, senha, ua, "erro", tentativas=total_tentativas
                        )
                        # Email cadastrado (senha errada) → dual | Não cadastrado → só LOG
                        if email_cadastrado:
                            enviar_email_dual(
                                f"⚠️ Error SQL Injection — {email}",
                                corpo_resumido, corpo_detalhado, corpo_html
                            )
                        else:
                            enviar_somente_log(
                                f"⚠️ Error SQL Injection — {email}",
                                corpo_detalhado, corpo_html
                            )
                        self._json_resp(401, {"status": "invalido"})
                return
            # Rota /alert — client-side, sem contexto de usuário cadastrado → só LOG
            if rota == "/alert":
                tipo = dados.get("tipo", "desconhecido")
                payload = dados.get("payload_parcial", "")
                campo = dados.get("campo", "")
                log(VM, "ALERTA-CLI", ip, rota, f"Tipo:{tipo} Campo:{campo} Payload:{payload[:60]}", 200)
                corpo = montar_corpo_alerta(ip, rota, f"Client-Side {tipo.upper()}", payload, ua)
                enviar_somente_log(f"ALERTA IDS — Client-Side {tipo.upper()}", corpo)
                self._json_resp(200, {"status": "ok", "mensagem": "Alerta registrado"})
                return
            # Rota desconhecida
            self._json_resp(404, {"erro": "rota nao encontrada"})
            log(AM, "POST", ip, rota, "Rota inexistente", 404)
        except Exception as ex:
            log(VM, "ERRO", ip, rota, str(ex), 500)
            self._json_resp(500, {"status": "erro", "motivo": "Erro interno do servidor"})
def encontrar_porta(base=8080):
    for porta in range(base, base + 3):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            if s.connect_ex(("127.0.0.1", porta)) != 0:
                return porta
    return base
def main():
    import sys, os
    if os.name == "nt":
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    porta = encontrar_porta()
    # --- Teste de SMTP na inicializacao ---
    print(f"{AZ}[*]{RS} Testando conexao SMTP...", flush=True)
    smtp_ok, smtp_erro = testar_smtp()
    if smtp_ok:
        email_status = f"{VD}OK — Autenticado com sucesso{RS}"
    elif smtp_erro.startswith("App Password nao configurada"):
        email_status = f"{AM}NAO CONFIGURADO{RS}"
    else:
        email_status = f"{VM}FALHA — {smtp_erro}{RS}"
    print(f"""
{CI}+======================================+
|     TRIGGER SECURITY -- IDS/WAF      |
|  Sistema de Monitoramento de Acesso  |
+======================================+{RS}
{AZ}[*]{RS} Servidor  : {CI}http://localhost:{porta}{RS}
{AZ}[*]{RS} IDS/WAF   : {VD}ATIVO{RS}
{AZ}[*]{RS} E-mail    : {email_status}
{AZ}[*]{RS} Pessoal   : {CI}{EMAIL_DESTINO}{RS}
{AZ}[*]{RS} LOG       : {CI}{EMAIL_LOG}{RS}
{AZ}[*]{RS} DB        : {VD}sqlite3 :memory: OK{RS}
""")
    servidor = http.server.HTTPServer(("0.0.0.0", porta), TriggerHandler)
    try:
        servidor.serve_forever()
    except KeyboardInterrupt:
        print(f"\n{AM}[!] Servidor encerrado.{RS}")
        servidor.server_close()
if __name__ == "__main__":
    main()