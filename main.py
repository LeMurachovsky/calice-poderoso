"""
Cálice Poderoso — Core Engine v2

Camada de governança human-in-the-loop para decisões de IA:

  1. A IA submete uma proposta ............ POST /api/v1/intercept
  2. O motor de regras diagnostica violações e, se houver, ativa o fator de pausa
  3. Um operador humano decide ............ POST /api/v1/seal   (chancela)
                                            POST /api/v1/reject (rejeição)
  4. Cada evento entra num livro-razão append-only, encadeado e assinado duas vezes:
     HMAC-SHA256 (elo da cadeia) e Ed25519 (assinatura pública)
  5. Qualquer auditor confere o livro ..... GET  /api/v1/ledger/verify
  6. Terceiros conferem sem segredo ....... GET  /api/v1/ledger/export + verificar_publico.py
  7. Janelas concorrentes compartilham o que já foi chancelado num tópico:
       registra o desfecho ................ POST /api/v1/topics/{topic_id}/outcomes
       monta o contexto da próxima janela . GET  /api/v1/topics/{topic_id}/context

Só operadores autenticados decidem: POST /api/v1/auth/login troca login e senha por um
token de sessão, exigido (Authorization: Bearer) na chancela e na rejeição. Contas são
criadas pela linha de comando:  python main.py operador criar <login> "<Nome completo>"

Configuração por variáveis de ambiente:
  CALICE_SIGNING_KEY           chave secreta das assinaturas (obrigatória em produção)
  CALICE_ED25519_SEED          semente Ed25519 em hex (32 bytes); se ausente, derivada da anterior
  CALICE_DB_PATH               caminho do SQLite (padrão: ./calice.db)
  CALICE_CONFIDENCE_THRESHOLD  confiança mínima exigida da IA (padrão: 0.85)
  CALICE_SESSION_HOURS         validade do token de sessão, em horas (padrão: 8)
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import sqlite3
import uuid
from collections.abc import Callable, Iterator
from contextlib import asynccontextmanager, contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Literal, Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi import Path as PathParam
from fastapi.responses import FileResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict, Field

import verificar_publico as vp

log = logging.getLogger("calice")

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
GENESIS_HASH = "0" * 64
DEV_SIGNING_KEY = "calice-dev-key-nao-use-em-producao"
PADRAO_SELO = "CUSTODIA_PROBATORIA_CPC"


# ───────────────────────────── Configuração ─────────────────────────────

@dataclass(frozen=True)
class Settings:
    db_path: str
    signing_key: bytes
    dev_key: bool
    confidence_threshold: float
    session_hours: float
    ed25519_key: Ed25519PrivateKey

    @property
    def chave_publica_hex(self) -> str:
        return self.ed25519_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()


def carregar_ed25519(signing_key: bytes) -> Ed25519PrivateKey:
    """Semente explícita em CALICE_ED25519_SEED ou, na falta dela, derivada da chave HMAC.

    Derivar mantém instalações existentes funcionando com um segredo só; a semente
    própria permite girar as duas chaves de forma independente.
    """
    semente_hex = os.getenv("CALICE_ED25519_SEED")
    if semente_hex:
        semente = bytes.fromhex(semente_hex.strip())
        if len(semente) != 32:
            raise ValueError("CALICE_ED25519_SEED deve ter 32 bytes (64 caracteres hex).")
    else:
        semente = hashlib.sha256(b"calice-ed25519-v1:" + signing_key).digest()
    return Ed25519PrivateKey.from_private_bytes(semente)


def load_settings() -> Settings:
    key = os.getenv("CALICE_SIGNING_KEY")
    signing_key = (key or DEV_SIGNING_KEY).encode("utf-8")
    return Settings(
        db_path=os.getenv("CALICE_DB_PATH", str(BASE_DIR / "calice.db")),
        signing_key=signing_key,
        dev_key=not key,
        confidence_threshold=float(os.getenv("CALICE_CONFIDENCE_THRESHOLD", "0.85")),
        session_hours=float(os.getenv("CALICE_SESSION_HOURS", "8")),
        ed25519_key=carregar_ed25519(signing_key),
    )


settings = load_settings()  # recarregado no startup (lifespan)


class Status(str, Enum):
    PAUSA = "FATOR_DE_PAUSA_ATIVADO"
    PRONTO = "PRONTO_PARA_CHANCELA"
    CHANCELADO = "CHANCELADO_E_CONCLUIDO"
    REJEITADO = "REJEITADO"


FINAIS = {Status.CHANCELADO.value, Status.REJEITADO.value}


# ─────────────────────────────── Contratos ───────────────────────────────

# Tópicos e janelas entram no texto do contexto: sem espaços nem quebras de linha,
# para que um identificador não consiga forjar linhas de "fatos chancelados".
IDENTIFICADOR_VALIDO = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,119}$"
MAX_DADOS_DESFECHO = 10_000

class InterceptRequest(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    document_id: str = Field(min_length=1, max_length=120)
    content: str = Field(min_length=1, max_length=20_000)
    liability_clause: bool
    confidence_score: float = Field(ge=0.0, le=1.0)


class LoginRequest(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    login: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class DesfechoRequest(BaseModel):
    """Desfecho de uma janela, amarrado a uma transação já chancelada."""
    model_config = ConfigDict(str_strip_whitespace=True)

    transaction_id: str = Field(min_length=1)
    janela: str = Field(min_length=1, max_length=120, pattern=IDENTIFICADOR_VALIDO,
                        description="Identificador da janela (sessão/conversa) de origem.")
    dados: dict[str, Any] = Field(description="Parâmetros fixados pela janela.")


class DecisionRequest(BaseModel):
    """O operador não é informado aqui: ele vem da sessão autenticada."""
    model_config = ConfigDict(str_strip_whitespace=True)

    transaction_id: str = Field(min_length=1)
    notes: str = Field(
        min_length=15, max_length=2_000,
        description="Justificativa obrigatória: é ela que materializa o juízo humano.",
    )
    acknowledged_violations: list[str] = Field(
        default_factory=list,
        description="Códigos das violações das quais o operador declara ciência.",
    )


# ──────────────────────────── Motor de regras ────────────────────────────

@dataclass(frozen=True)
class Violacao:
    codigo: str
    severidade: Literal["CRITICA", "ALTA", "MEDIA"]
    mensagem: str


Regra = Callable[[InterceptRequest, Settings], Optional[Violacao]]
REGRAS: list[Regra] = []


def regra(fn: Regra) -> Regra:
    """Registra uma regra. Nova política = nova função decorada, sem tocar nos endpoints."""
    REGRAS.append(fn)
    return fn


@regra
def clausula_de_responsabilidade(req: InterceptRequest, cfg: Settings) -> Violacao | None:
    if not req.liability_clause:
        return Violacao("LACUNA_JURIDICA", "CRITICA", "Cláusula de responsabilidade ausente.")
    return None


@regra
def confianca_minima(req: InterceptRequest, cfg: Settings) -> Violacao | None:
    if req.confidence_score < cfg.confidence_threshold:
        return Violacao(
            "CONFIANCA_BAIXA", "ALTA",
            f"Confiança da IA abaixo do limiar "
            f"({req.confidence_score:.2f} < {cfg.confidence_threshold:.2f}).",
        )
    return None


def diagnosticar(req: InterceptRequest, cfg: Settings) -> list[Violacao]:
    return [v for r in REGRAS if (v := r(req, cfg)) is not None]


# ─────────────────────────────── Utilidades ──────────────────────────────

def agora() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def novo_id(prefixo: str) -> str:
    return f"{prefixo}-{datetime.now(timezone.utc):%Y%m%d}-{uuid.uuid4().hex[:12].upper()}"


canonico = vp.canonico  # uma única definição, compartilhada com o verificador público


def sha256_hex(texto: str) -> str:
    return hashlib.sha256(texto.encode("utf-8")).hexdigest()


# ──────────────────────────── Banco de dados ─────────────────────────────

SCHEMA = """
CREATE TABLE IF NOT EXISTS transacoes (
    tx_id            TEXT PRIMARY KEY,
    document_id      TEXT NOT NULL,
    content          TEXT NOT NULL,
    liability_clause INTEGER NOT NULL,
    confidence_score REAL NOT NULL,
    status           TEXT NOT NULL,
    violations       TEXT NOT NULL,
    created_at       TEXT NOT NULL,
    decisao_id       TEXT UNIQUE,
    operador         TEXT,
    justificativa    TEXT,
    decided_at       TEXT,
    proof_hash       TEXT UNIQUE
);
CREATE INDEX IF NOT EXISTS idx_transacoes_status ON transacoes(status);

CREATE TABLE IF NOT EXISTS ledger (
    seq        INTEGER PRIMARY KEY,
    tx_id      TEXT NOT NULL REFERENCES transacoes(tx_id),
    evento     TEXT NOT NULL,
    dados      TEXT NOT NULL,
    prev_hash  TEXT NOT NULL,
    hash       TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    assinatura TEXT  -- Ed25519 (hex); NULL em registros anteriores à assinatura pública
);
CREATE INDEX IF NOT EXISTS idx_ledger_tx ON ledger(tx_id);

-- Projeção dos eventos SINCRONIZACAO do livro, indexada por tópico (como `transacoes`).
CREATE TABLE IF NOT EXISTS desfechos_topico (
    ledger_seq      INTEGER PRIMARY KEY REFERENCES ledger(seq),
    topic_id        TEXT NOT NULL,
    janela          TEXT NOT NULL,
    tx_id           TEXT NOT NULL REFERENCES transacoes(tx_id),
    dados           TEXT NOT NULL,
    hash_certidao   TEXT NOT NULL,
    operador_login  TEXT NOT NULL,
    sincronizado_em TEXT NOT NULL,
    UNIQUE (topic_id, tx_id)
);
CREATE INDEX IF NOT EXISTS idx_desfechos_topico ON desfechos_topico(topic_id, ledger_seq);

CREATE TABLE IF NOT EXISTS operadores (
    login      TEXT PRIMARY KEY,
    nome       TEXT NOT NULL,
    senha_hash TEXT NOT NULL,
    ativo      INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL
);

-- Guarda só o SHA-256 do token: quem lê o arquivo não consegue usar sessões vivas.
CREATE TABLE IF NOT EXISTS sessoes (
    token_sha256 TEXT PRIMARY KEY,
    login        TEXT NOT NULL REFERENCES operadores(login),
    created_at   TEXT NOT NULL,
    expira_em    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessoes_login ON sessoes(login);

-- Defesa em profundidade contra bugs da aplicação (não contra quem tem o arquivo:
-- esse caso é coberto pelas assinaturas HMAC e Ed25519 + /ledger/verify).
CREATE TRIGGER IF NOT EXISTS ledger_sem_update BEFORE UPDATE ON ledger
BEGIN SELECT RAISE(ABORT, 'ledger é append-only'); END;
CREATE TRIGGER IF NOT EXISTS ledger_sem_delete BEFORE DELETE ON ledger
BEGIN SELECT RAISE(ABORT, 'ledger é append-only'); END;
"""


def conectar() -> sqlite3.Connection:
    conn = sqlite3.connect(settings.db_path, timeout=10, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")  # SQLite ignora FKs sem isto
    return conn


@contextmanager
def leitura() -> Iterator[sqlite3.Connection]:
    conn = conectar()
    try:
        yield conn
    finally:
        conn.close()


@contextmanager
def escrita() -> Iterator[sqlite3.Connection]:
    """Transação que pega o lock de escrita já no início (BEGIN IMMEDIATE).

    Isso serializa os escritores: ler o último hash e gravar o próximo, ou checar o
    status e selar, viram operações atômicas. Sem isso, duas requisições simultâneas
    leem o mesmo estado e ambas "vencem".
    """
    conn = conectar()
    try:
        conn.execute("BEGIN IMMEDIATE")
        yield conn
        conn.execute("COMMIT")
    except BaseException:
        if conn.in_transaction:
            conn.execute("ROLLBACK")
        raise
    finally:
        conn.close()


def init_db() -> None:
    with leitura() as conn:
        conn.execute("PRAGMA journal_mode = WAL")
        conn.executescript(SCHEMA)
        colunas = {c["name"] for c in conn.execute("PRAGMA table_info(ledger)")}
        if "assinatura" not in colunas:  # bancos criados antes da assinatura pública
            conn.execute("ALTER TABLE ledger ADD COLUMN assinatura TEXT")


# ───────────────────────────── Autenticação ──────────────────────────────

LOGIN_VALIDO = r"^[a-z0-9][a-z0-9._-]{2,63}$"
SCRYPT_N, SCRYPT_R, SCRYPT_P = 2**14, 8, 1


@dataclass(frozen=True)
class Operador:
    login: str
    nome: str


def hash_senha(senha: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(senha.encode("utf-8"), salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
    return f"scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${salt.hex()}${digest.hex()}"


def conferir_senha(senha: str, armazenado: str) -> bool:
    try:
        algoritmo, n, r, p, salt, digest = armazenado.split("$")
    except ValueError:
        return False
    if algoritmo != "scrypt":
        return False
    calculado = hashlib.scrypt(senha.encode("utf-8"), salt=bytes.fromhex(salt),
                               n=int(n), r=int(r), p=int(p))
    return hmac.compare_digest(calculado.hex(), digest)


# Conferida quando o login não existe, para que o tempo de resposta não revele quais logins existem.
_HASH_FICTICIO = hash_senha(secrets.token_hex(16))


def criar_operador(login: str, nome: str, senha: str) -> Operador:
    login = login.strip().lower()
    nome = " ".join(nome.split())
    if not re.fullmatch(LOGIN_VALIDO, login):
        raise ValueError("Login inválido: 3 a 64 caracteres entre a-z, 0-9, '.', '_' e '-'.")
    if not 3 <= len(nome) <= 120:
        raise ValueError("O nome deve ter entre 3 e 120 caracteres.")
    if len(senha) < 12:
        raise ValueError("A senha deve ter pelo menos 12 caracteres.")
    with escrita() as conn:
        if conn.execute("SELECT 1 FROM operadores WHERE login = ?", (login,)).fetchone():
            raise ValueError(f"O login '{login}' já existe.")
        conn.execute("INSERT INTO operadores (login, nome, senha_hash, ativo, created_at) "
                     "VALUES (?, ?, ?, 1, ?)", (login, nome, hash_senha(senha), agora()))
    return Operador(login, nome)


def definir_senha(login: str, senha: str) -> None:
    if len(senha) < 12:
        raise ValueError("A senha deve ter pelo menos 12 caracteres.")
    with escrita() as conn:
        if conn.execute("UPDATE operadores SET senha_hash = ? WHERE login = ?",
                        (hash_senha(senha), login)).rowcount == 0:
            raise ValueError(f"O login '{login}' não existe.")
        conn.execute("DELETE FROM sessoes WHERE login = ?", (login,))


def definir_ativo(login: str, ativo: bool) -> None:
    with escrita() as conn:
        if conn.execute("UPDATE operadores SET ativo = ? WHERE login = ?",
                        (int(ativo), login)).rowcount == 0:
            raise ValueError(f"O login '{login}' não existe.")
        if not ativo:
            conn.execute("DELETE FROM sessoes WHERE login = ?", (login,))


def abrir_sessao(login: str, senha: str) -> tuple[str, str, Operador] | None:
    """Confere a senha e devolve (token, expira_em, operador), ou None se não conferir."""
    with leitura() as conn:
        op = conn.execute("SELECT * FROM operadores WHERE login = ?", (login.lower(),)).fetchone()
    senha_ok = conferir_senha(senha, op["senha_hash"] if op else _HASH_FICTICIO)
    if op is None or not senha_ok or not op["ativo"]:
        return None
    token = secrets.token_urlsafe(32)
    criada = datetime.now(timezone.utc)
    expira_em = (criada + timedelta(hours=settings.session_hours)).isoformat(timespec="milliseconds")
    with escrita() as conn:
        conn.execute("DELETE FROM sessoes WHERE expira_em <= ?", (agora(),))
        conn.execute("INSERT INTO sessoes (token_sha256, login, created_at, expira_em) VALUES (?, ?, ?, ?)",
                     (sha256_hex(token), op["login"], criada.isoformat(timespec="milliseconds"), expira_em))
    return token, expira_em, Operador(op["login"], op["nome"])


def fechar_sessao(token: str) -> None:
    with escrita() as conn:
        conn.execute("DELETE FROM sessoes WHERE token_sha256 = ?", (sha256_hex(token),))


_bearer = HTTPBearer(auto_error=False)
NAO_AUTENTICADO = {"WWW-Authenticate": "Bearer"}


def token_da_requisicao(cred: Optional[HTTPAuthorizationCredentials] = Depends(_bearer)) -> str:
    if cred is None or cred.scheme.lower() != "bearer" or not cred.credentials:
        raise HTTPException(401, "Autenticação necessária: faça login como operador.", headers=NAO_AUTENTICADO)
    return cred.credentials


def operador_autenticado(token: str = Depends(token_da_requisicao)) -> Operador:
    with leitura() as conn:
        row = conn.execute(
            "SELECT o.login, o.nome FROM sessoes s JOIN operadores o ON o.login = s.login "
            "WHERE s.token_sha256 = ? AND s.expira_em > ? AND o.ativo = 1",
            (sha256_hex(token), agora())).fetchone()
    if row is None:
        raise HTTPException(401, "Sessão inválida ou expirada: faça login novamente.", headers=NAO_AUTENTICADO)
    return Operador(row["login"], row["nome"])


# ────────────────────────────── Livro-razão ──────────────────────────────

def assinar(seq: int, tx_id: str, evento: str, dados: str, prev_hash: str, created_at: str) -> str:
    envelope = canonico({
        "seq": seq, "tx_id": tx_id, "evento": evento,
        "dados": dados, "prev_hash": prev_hash, "created_at": created_at,
    })
    return hmac.new(settings.signing_key, envelope.encode("utf-8"), hashlib.sha256).hexdigest()


def registrar_evento(conn: sqlite3.Connection, tx_id: str, evento: str,
                     dados: dict[str, Any], created_at: str) -> dict[str, Any]:
    """Anexa um evento ao livro. Deve rodar dentro de `escrita()`."""
    ultimo = conn.execute("SELECT seq, hash FROM ledger ORDER BY seq DESC LIMIT 1").fetchone()
    seq = ultimo["seq"] + 1 if ultimo else 1
    prev_hash = ultimo["hash"] if ultimo else GENESIS_HASH
    dados_json = canonico(dados)
    digest = assinar(seq, tx_id, evento, dados_json, prev_hash, created_at)
    registro = {"seq": seq, "tx_id": tx_id, "evento": evento, "dados": dados_json,
                "prev_hash": prev_hash, "hash": digest, "created_at": created_at}
    assinatura = settings.ed25519_key.sign(vp.mensagem_assinada(registro)).hex()
    conn.execute(
        "INSERT INTO ledger (seq, tx_id, evento, dados, prev_hash, hash, created_at, assinatura) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (seq, tx_id, evento, dados_json, prev_hash, digest, created_at, assinatura),
    )
    return {"seq": seq, "evento": evento, "prev_hash": prev_hash, "hash": digest,
            "created_at": created_at, "assinatura": assinatura}


def chave_publica() -> dict[str, str]:
    pub = settings.chave_publica_hex
    return {"algoritmo": vp.ALGORITMO, "hex": pub, "id": vp.id_chave(pub)}


def registros_publicos(rows: list[sqlite3.Row]) -> list[dict[str, Any]]:
    return [{c: r[c] for c in (*vp.CAMPOS, "assinatura")} for r in rows]


def verificar_ledger(conn: sqlite3.Connection) -> dict[str, Any]:
    total = 0

    def falha(seq: int | None, motivo: str) -> dict[str, Any]:
        return {"integro": False, "total_eventos": total, "head_hash": None,
                "falha": {"seq": seq, "motivo": motivo}, "verificado_em": agora()}

    # 1) A cadeia em si: sequência contínua, encadeamento e assinatura de cada elo.
    prev = GENESIS_HASH
    pub = vp.carregar_chave(settings.chave_publica_hex)
    eventos: dict[str, dict[str, sqlite3.Row]] = {}
    por_seq: dict[int, sqlite3.Row] = {}
    for ev in conn.execute("SELECT * FROM ledger ORDER BY seq"):
        total += 1
        if ev["seq"] != total:
            return falha(ev["seq"], f"Lacuna na sequência: esperado o registro #{total}.")
        if ev["prev_hash"] != prev:
            return falha(ev["seq"], "Encadeamento rompido: o registro não aponta para o anterior.")
        esperado = assinar(ev["seq"], ev["tx_id"], ev["evento"], ev["dados"], ev["prev_hash"], ev["created_at"])
        if not hmac.compare_digest(esperado, ev["hash"]):
            return falha(ev["seq"], "Assinatura inválida: o conteúdo do registro foi alterado.")
        # Registros legados (sem Ed25519) seguem protegidos pelo HMAC acima.
        if ev["assinatura"] is not None and not vp.assinatura_valida(pub, dict(ev)):
            return falha(ev["seq"], "Assinatura Ed25519 inválida: registro alterado ou chave diferente.")
        eventos.setdefault(ev["tx_id"], {})[ev["evento"]] = ev
        por_seq[ev["seq"]] = ev
        prev = ev["hash"]

    # 2) A tabela `transacoes` é só uma projeção; ela precisa bater com o livro.
    for tx in conn.execute("SELECT tx_id, content, status, proof_hash FROM transacoes"):
        evs = eventos.get(tx["tx_id"], {})
        origem = evs.get("INTERCEPTACAO")
        if origem is None:
            return falha(None, f"{tx['tx_id']} existe sem registro de interceptação no livro.")
        dados_origem = json.loads(origem["dados"])
        if sha256_hex(tx["content"]) != dados_origem["content_sha256"]:
            return falha(origem["seq"], f"O conteúdo de {tx['tx_id']} diverge do registrado.")
        decisao = evs.get("CHANCELA") or evs.get("REJEICAO")
        status_esperado = json.loads(decisao["dados"])["status"] if decisao else dados_origem["status"]
        if tx["status"] != status_esperado:
            return falha(origem["seq"], f"O status de {tx['tx_id']} diverge do registrado.")
        if decisao and tx["proof_hash"] != decisao["hash"]:
            return falha(decisao["seq"], f"O selo de {tx['tx_id']} diverge do registrado.")

    # 3) Os desfechos de tópico também são projeção: cada um aponta para o seu evento.
    sincronizados = {s for s, ev in por_seq.items() if ev["evento"] == "SINCRONIZACAO"}
    for d in conn.execute("SELECT * FROM desfechos_topico ORDER BY ledger_seq"):
        ev = por_seq.get(d["ledger_seq"])
        if ev is None or ev["evento"] != "SINCRONIZACAO" or ev["tx_id"] != d["tx_id"]:
            return falha(d["ledger_seq"], f"Desfecho do tópico {d['topic_id']} sem evento correspondente no livro.")
        if json.loads(ev["dados"]) != desfecho_no_livro(d):
            return falha(d["ledger_seq"], f"Desfecho do tópico {d['topic_id']} diverge do registrado.")
        sincronizados.discard(d["ledger_seq"])
    if sincronizados:
        return falha(min(sincronizados), "Evento de sincronização sem desfecho correspondente.")

    return {"integro": True, "total_eventos": total, "head_hash": prev,
            "falha": None, "verificado_em": agora()}


# ──────────────────── Sincronização entre janelas ────────────────────────
#
# Várias janelas (sessões de IA) podem tratar do mesmo assunto ao mesmo tempo. Para que
# a janela B não contradiga o que a janela A já fechou, cada desfecho chancelado é
# publicado num tópico, e a janela seguinte recebe essa linha do tempo como contexto.
#
# Só entra no tópico o que um operador já chancelou: a certidão é o proof_hash da
# transação (o hash do evento CHANCELA), lido do banco, nunca informado pelo cliente.
# O registro vira um evento SINCRONIZACAO no livro, assinado como qualquer outro.

def desfecho_no_livro(d: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
    """Dados do evento SINCRONIZACAO correspondentes a uma linha de `desfechos_topico`."""
    return {"topic_id": d["topic_id"], "janela": d["janela"], "dados": json.loads(d["dados"]),
            "hash_certidao": d["hash_certidao"], "operador_login": d["operador_login"]}


def registrar_desfecho_janela(topic_id: str, janela: str, tx_id: str,
                              dados: dict[str, Any], operador: Operador) -> dict[str, Any]:
    dados_json = canonico(dados)
    if len(dados_json) > MAX_DADOS_DESFECHO:
        raise HTTPException(422, f"Os dados do desfecho passam de {MAX_DADOS_DESFECHO} caracteres.")
    with escrita() as conn:
        tx = conn.execute("SELECT tx_id, status, proof_hash FROM transacoes WHERE tx_id = ?",
                          (tx_id,)).fetchone()
        if tx is None:
            raise HTTPException(404, "Transação não encontrada.")
        if tx["status"] != Status.CHANCELADO.value:
            raise HTTPException(409, "Só desfechos chancelados entram no tópico "
                                     f"(status atual: {tx['status']}).")
        if conn.execute("SELECT 1 FROM desfechos_topico WHERE topic_id = ? AND tx_id = ?",
                        (topic_id, tx_id)).fetchone():
            raise HTTPException(409, f"Esta transação já foi sincronizada no tópico {topic_id}.")
        linha = {"topic_id": topic_id, "janela": janela, "tx_id": tx_id, "dados": dados_json,
                 "hash_certidao": tx["proof_hash"], "operador_login": operador.login,
                 "sincronizado_em": agora()}
        evento = registrar_evento(conn, tx_id, "SINCRONIZACAO", desfecho_no_livro(linha),
                                  linha["sincronizado_em"])
        conn.execute(
            "INSERT INTO desfechos_topico (ledger_seq, topic_id, janela, tx_id, dados, hash_certidao, "
            "operador_login, sincronizado_em) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (evento["seq"], topic_id, janela, tx_id, dados_json, linha["hash_certidao"],
             operador.login, linha["sincronizado_em"]))
    return {**serializar_desfecho({**linha, "ledger_seq": evento["seq"]}), "ledger": evento}


def serializar_desfecho(d: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
    return {"ledger_seq": d["ledger_seq"], "janela": d["janela"], "transaction_id": d["tx_id"],
            "dados": json.loads(d["dados"]), "hash_certidao": d["hash_certidao"],
            "operador_login": d["operador_login"], "sincronizado_em": d["sincronizado_em"]}


def historico_topico(conn: sqlite3.Connection, topic_id: str) -> list[dict[str, Any]]:
    rows = conn.execute("SELECT * FROM desfechos_topico WHERE topic_id = ? ORDER BY ledger_seq",
                        (topic_id,)).fetchall()
    return [serializar_desfecho(r) for r in rows]


def preparar_contexto_proxima_janela(historico: list[dict[str, Any]]) -> str:
    """Linha do tempo canônica, em texto, para injetar no prompt da próxima janela."""
    if not historico:
        return "Nenhum contexto prévio registrado para este tópico."
    linhas = ["FATOS E DELIBERAÇÕES ANTERIORES CHANCELADOS:"]
    for item in historico:
        linhas.append(
            f"- [{item['sincronizado_em']}] Origem: {item['janela']} | "
            f"Certidão: {item['hash_certidao'][:12]}... | "
            f"Parâmetros Fixados: {canonico(item['dados'])}"
        )
    return "\n".join(linhas) + "\n"


# ───────────────────────────── Serialização ──────────────────────────────

def serializar(tx: sqlite3.Row, com_conteudo: bool = False) -> dict[str, Any]:
    d: dict[str, Any] = {
        "transaction_id": tx["tx_id"],
        "document_id": tx["document_id"],
        "status": tx["status"],
        "confidence_score": tx["confidence_score"],
        "liability_clause": bool(tx["liability_clause"]),
        "violations": json.loads(tx["violations"]),
        "created_at": tx["created_at"],
        "decisao": None,
    }
    if tx["decisao_id"]:
        d["decisao"] = {
            "id": tx["decisao_id"],
            "operador": tx["operador"],
            "justificativa": tx["justificativa"],
            "decided_at": tx["decided_at"],
            "proof_hash": tx["proof_hash"],
        }
    if com_conteudo:
        d["content"] = tx["content"]
    return d


# ─────────────────────────────── Aplicação ───────────────────────────────

@asynccontextmanager
async def lifespan(_: FastAPI):
    global settings
    settings = load_settings()
    init_db()
    if settings.dev_key:
        log.warning("CALICE_SIGNING_KEY não definida: usando chave de DESENVOLVIMENTO. "
                    "Selos emitidos assim não têm valor fora deste ambiente.")
    yield


app = FastAPI(title="Cálice Poderoso — Core Engine", version="2.0.0", lifespan=lifespan)


@app.post("/api/v1/intercept", status_code=201)
def intercept(req: InterceptRequest) -> dict[str, Any]:
    violacoes = diagnosticar(req, settings)
    status = Status.PAUSA if violacoes else Status.PRONTO
    tx_id = novo_id("TX")
    created_at = agora()

    with escrita() as conn:
        conn.execute(
            "INSERT INTO transacoes (tx_id, document_id, content, liability_clause, "
            "confidence_score, status, violations, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (tx_id, req.document_id, req.content, int(req.liability_clause), req.confidence_score,
             status.value, canonico([asdict(v) for v in violacoes]), created_at),
        )
        evento = registrar_evento(conn, tx_id, "INTERCEPTACAO", {
            "document_id": req.document_id,
            "content_sha256": sha256_hex(req.content),
            "liability_clause": req.liability_clause,
            "confidence_score": req.confidence_score,
            "confidence_threshold": settings.confidence_threshold,
            "violations": [asdict(v) for v in violacoes],
            "status": status.value,
        }, created_at)

    return {
        "transaction_id": tx_id,
        "status": status.value,
        "violations": [asdict(v) for v in violacoes],
        "input_data": req.model_dump(),
        "hash_intermediario": evento["hash"],
        "ledger": evento,
    }


def _decidir(req: DecisionRequest, operador: Operador, aprovar: bool) -> dict[str, Any]:
    with escrita() as conn:
        tx = conn.execute("SELECT * FROM transacoes WHERE tx_id = ?", (req.transaction_id,)).fetchone()
        if tx is None:
            raise HTTPException(404, "Transação não encontrada.")
        if tx["status"] in FINAIS:
            raise HTTPException(409, f"Conflito: esta transação já foi decidida ({tx['status']}).")

        codigos = {v["codigo"] for v in json.loads(tx["violations"])}
        if aprovar:
            sem_ciencia = sorted(codigos - set(req.acknowledged_violations))
            if sem_ciencia:
                raise HTTPException(422, {
                    "mensagem": "Declare ciência de todas as violações antes de chancelar.",
                    "violacoes_sem_ciencia": sem_ciencia,
                })

        decided_at = agora()
        novo_status = Status.CHANCELADO if aprovar else Status.REJEITADO
        decisao_id = novo_id("SEAL-CALICE" if aprovar else "REJ-CALICE")
        evento = registrar_evento(conn, tx["tx_id"], "CHANCELA" if aprovar else "REJEICAO", {
            "decisao_id": decisao_id,
            "operador": operador.nome,
            "operador_login": operador.login,
            "justificativa": req.notes,
            "violacoes_reconhecidas": sorted(codigos & set(req.acknowledged_violations)),
            "status_anterior": tx["status"],
            "status": novo_status.value,
        }, decided_at)
        conn.execute(
            "UPDATE transacoes SET status = ?, decisao_id = ?, operador = ?, justificativa = ?, "
            "decided_at = ?, proof_hash = ? WHERE tx_id = ?",
            (novo_status.value, decisao_id, operador.nome, req.notes,
             decided_at, evento["hash"], tx["tx_id"]),
        )

    return {
        "transaction_id": req.transaction_id,
        "status": novo_status.value,
        "juizo_humano": {
            "operator": operador.nome,
            "operator_login": operador.login,
            "justification": req.notes,
            "acknowledged_violations": sorted(codigos & set(req.acknowledged_violations)),
            "signed_at": decided_at,
        },
        ("selo_calice" if aprovar else "registro_rejeicao"): {
            "seal_id": decisao_id,
            "proof_hash": evento["hash"],
            "ledger_seq": evento["seq"],
            "padrao": PADRAO_SELO,
            "assinatura": evento["assinatura"],
            "chave_publica": chave_publica(),
        },
    }


@app.post("/api/v1/seal")
def seal(req: DecisionRequest, operador: Operador = Depends(operador_autenticado)) -> dict[str, Any]:
    return _decidir(req, operador, aprovar=True)


@app.post("/api/v1/reject")
def reject(req: DecisionRequest, operador: Operador = Depends(operador_autenticado)) -> dict[str, Any]:
    return _decidir(req, operador, aprovar=False)


TopicId = PathParam(pattern=IDENTIFICADOR_VALIDO, max_length=120)


@app.post("/api/v1/topics/{topic_id}/outcomes", status_code=201)
def publicar_desfecho(req: DesfechoRequest, topic_id: str = TopicId,
                      operador: Operador = Depends(operador_autenticado)) -> dict[str, Any]:
    return {"topic_id": topic_id,
            **registrar_desfecho_janela(topic_id, req.janela, req.transaction_id, req.dados, operador)}


@app.get("/api/v1/topics/{topic_id}/context")
def contexto_topico(topic_id: str = TopicId) -> dict[str, Any]:
    with leitura() as conn:
        historico = historico_topico(conn, topic_id)
    return {"topic_id": topic_id, "itens": historico,
            "contexto": preparar_contexto_proxima_janela(historico)}


@app.post("/api/v1/auth/login")
def login(req: LoginRequest) -> dict[str, Any]:
    sessao = abrir_sessao(req.login, req.password)
    if sessao is None:
        raise HTTPException(401, "Login ou senha inválidos.", headers=NAO_AUTENTICADO)
    token, expira_em, operador = sessao
    return {"token": token, "token_type": "bearer", "expires_at": expira_em, "operador": asdict(operador)}


@app.post("/api/v1/auth/logout", status_code=204)
def logout(token: str = Depends(token_da_requisicao)) -> None:
    fechar_sessao(token)


@app.get("/api/v1/auth/me")
def quem_sou(operador: Operador = Depends(operador_autenticado)) -> dict[str, Any]:
    return asdict(operador)


@app.get("/api/v1/transactions")
def listar(status: Optional[Status] = None, limit: int = Query(100, ge=1, le=500)) -> dict[str, Any]:
    with leitura() as conn:
        if status:
            rows = conn.execute(
                "SELECT * FROM transacoes WHERE status = ? ORDER BY created_at DESC, rowid DESC LIMIT ?",
                (status.value, limit)).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM transacoes ORDER BY created_at DESC, rowid DESC LIMIT ?",
                (limit,)).fetchall()
        contagem = {r[0]: r[1] for r in conn.execute(
            "SELECT status, COUNT(*) FROM transacoes GROUP BY status")}
    resumo = {s.value: contagem.get(s.value, 0) for s in Status}
    resumo["TOTAL"] = sum(contagem.values())
    return {"itens": [serializar(r) for r in rows], "resumo": resumo}


@app.get("/api/v1/transactions/{tx_id}")
def detalhar(tx_id: str) -> dict[str, Any]:
    with leitura() as conn:
        tx = conn.execute("SELECT * FROM transacoes WHERE tx_id = ?", (tx_id,)).fetchone()
        if tx is None:
            raise HTTPException(404, "Transação não encontrada.")
        eventos = conn.execute(
            "SELECT seq, evento, prev_hash, hash, created_at, assinatura FROM ledger "
            "WHERE tx_id = ? ORDER BY seq",
            (tx_id,)).fetchall()
    d = serializar(tx, com_conteudo=True)
    d["ledger"] = [dict(e) for e in eventos]
    d["limiar_confianca"] = settings.confidence_threshold
    return d


@app.get("/api/v1/ledger/verify")
def verificar() -> dict[str, Any]:
    with leitura() as conn:
        return verificar_ledger(conn)


@app.get("/api/v1/ledger/public-key")
def ler_chave_publica() -> dict[str, Any]:
    """Chave pública Ed25519 que confere todas as assinaturas do livro."""
    return {**chave_publica(), "chave_desenvolvimento": settings.dev_key}


@app.get("/api/v1/ledger/export")
def exportar() -> dict[str, Any]:
    """Livro completo, verificável offline com `verificar_publico.py` e a chave pública."""
    with leitura() as conn:
        rows = conn.execute("SELECT * FROM ledger ORDER BY seq").fetchall()
    return {"chave_publica": chave_publica(), "exportado_em": agora(),
            "registros": registros_publicos(rows)}


@app.get("/api/v1/transactions/{tx_id}/proof")
def provar(tx_id: str) -> dict[str, Any]:
    """Prova de uma transação: seus registros assinados, sem o conteúdo (só o hash dele)."""
    with leitura() as conn:
        rows = conn.execute("SELECT * FROM ledger WHERE tx_id = ? ORDER BY seq", (tx_id,)).fetchall()
    if not rows:
        raise HTTPException(404, "Transação não encontrada.")
    return {"transaction_id": tx_id, "chave_publica": chave_publica(),
            "registros": registros_publicos(rows)}


@app.get("/api/v1/health")
def health() -> dict[str, Any]:
    return {
        "status": "ok",
        "versao": app.version,
        "chave_desenvolvimento": settings.dev_key,
        "chave_publica_id": vp.id_chave(settings.chave_publica_hex),
        "limiar_confianca": settings.confidence_threshold,
        "regras": [r.__name__ for r in REGRAS],
        "padrao": PADRAO_SELO,
    }


@app.get("/", include_in_schema=False)
def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


# ─────────────────────────── Linha de comando ────────────────────────────

def cli(argv: list[str] | None = None) -> int:
    """Gestão de operadores:  python main.py operador {criar,senha,desativar,reativar,listar}"""
    import argparse
    import getpass

    parser = argparse.ArgumentParser(prog="python main.py", description="Cálice Poderoso: gestão de operadores")
    sub = parser.add_subparsers(dest="grupo", required=True)
    acoes = sub.add_parser("operador").add_subparsers(dest="acao", required=True)
    criar = acoes.add_parser("criar", help="cria um operador (pede a senha no terminal)")
    criar.add_argument("login")
    criar.add_argument("nome", help="nome completo, como aparecerá nos selos")
    for nome, ajuda in (("senha", "troca a senha e encerra as sessões abertas"),
                        ("desativar", "bloqueia o operador e encerra as sessões abertas"),
                        ("reativar", "desbloqueia o operador")):
        acoes.add_parser(nome, help=ajuda).add_argument("login")
    acoes.add_parser("listar", help="lista os operadores")
    args = parser.parse_args(argv)

    global settings
    settings = load_settings()
    init_db()

    def pedir_senha() -> str:
        senha = getpass.getpass("Senha (mín. 12 caracteres): ")
        if senha != getpass.getpass("Repita a senha: "):
            raise ValueError("As senhas não conferem.")
        return senha

    try:
        if args.acao == "criar":
            op = criar_operador(args.login, args.nome, pedir_senha())
            print(f"Operador criado: {op.login} ({op.nome})")
        elif args.acao == "senha":
            definir_senha(args.login, pedir_senha())
            print(f"Senha de {args.login} alterada.")
        elif args.acao in ("desativar", "reativar"):
            definir_ativo(args.login, args.acao == "reativar")
            print(f"Operador {args.login} {'reativado' if args.acao == 'reativar' else 'desativado'}.")
        else:
            with leitura() as conn:
                for r in conn.execute("SELECT login, nome, ativo FROM operadores ORDER BY login"):
                    print(f"{r['login']:<24} {r['nome']:<40} {'ativo' if r['ativo'] else 'desativado'}")
    except ValueError as e:
        print(f"Erro: {e}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(cli())
