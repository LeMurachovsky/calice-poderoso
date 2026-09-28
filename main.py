"""
Cálice Poderoso — Core Engine v2

Camada de governança human-in-the-loop para decisões de IA:

  1. A IA submete uma proposta ............ POST /api/v1/intercept
  2. O motor de regras diagnostica violações e, se houver, ativa o fator de pausa
  3. Um operador humano decide ............ POST /api/v1/seal   (chancela)
                                            POST /api/v1/reject (rejeição)
  4. Cada evento entra num livro-razão append-only, encadeado e assinado (HMAC-SHA256)
  5. Qualquer auditor confere o livro ..... GET  /api/v1/ledger/verify

Configuração por variáveis de ambiente:
  CALICE_SIGNING_KEY           chave secreta das assinaturas (obrigatória em produção)
  CALICE_DB_PATH               caminho do SQLite (padrão: ./calice.db)
  CALICE_CONFIDENCE_THRESHOLD  confiança mínima exigida da IA (padrão: 0.85)
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import sqlite3
import uuid
from collections.abc import Callable, Iterator
from contextlib import asynccontextmanager, contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Literal, Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse
from pydantic import BaseModel, ConfigDict, Field

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


def load_settings() -> Settings:
    key = os.getenv("CALICE_SIGNING_KEY")
    return Settings(
        db_path=os.getenv("CALICE_DB_PATH", str(BASE_DIR / "calice.db")),
        signing_key=(key or DEV_SIGNING_KEY).encode("utf-8"),
        dev_key=not key,
        confidence_threshold=float(os.getenv("CALICE_CONFIDENCE_THRESHOLD", "0.85")),
    )


settings = load_settings()  # recarregado no startup (lifespan)


class Status(str, Enum):
    PAUSA = "FATOR_DE_PAUSA_ATIVADO"
    PRONTO = "PRONTO_PARA_CHANCELA"
    CHANCELADO = "CHANCELADO_E_CONCLUIDO"
    REJEITADO = "REJEITADO"


FINAIS = {Status.CHANCELADO.value, Status.REJEITADO.value}


# ─────────────────────────────── Contratos ───────────────────────────────

class InterceptRequest(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    document_id: str = Field(min_length=1, max_length=120)
    content: str = Field(min_length=1, max_length=20_000)
    liability_clause: bool
    confidence_score: float = Field(ge=0.0, le=1.0)


class DecisionRequest(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)

    transaction_id: str = Field(min_length=1)
    operator_name: str = Field(min_length=3, max_length=120)
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


def canonico(obj: Any) -> str:
    """JSON determinístico: mesma entrada, mesmos bytes, mesmo hash."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


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
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ledger_tx ON ledger(tx_id);

-- Defesa em profundidade contra bugs da aplicação (não contra quem tem o arquivo:
-- esse caso é coberto pela assinatura HMAC + /ledger/verify).
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
    conn.execute(
        "INSERT INTO ledger (seq, tx_id, evento, dados, prev_hash, hash, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (seq, tx_id, evento, dados_json, prev_hash, digest, created_at),
    )
    return {"seq": seq, "evento": evento, "prev_hash": prev_hash, "hash": digest, "created_at": created_at}


def verificar_ledger(conn: sqlite3.Connection) -> dict[str, Any]:
    total = 0

    def falha(seq: int | None, motivo: str) -> dict[str, Any]:
        return {"integro": False, "total_eventos": total, "head_hash": None,
                "falha": {"seq": seq, "motivo": motivo}, "verificado_em": agora()}

    # 1) A cadeia em si: sequência contínua, encadeamento e assinatura de cada elo.
    prev = GENESIS_HASH
    eventos: dict[str, dict[str, sqlite3.Row]] = {}
    for ev in conn.execute("SELECT * FROM ledger ORDER BY seq"):
        total += 1
        if ev["seq"] != total:
            return falha(ev["seq"], f"Lacuna na sequência: esperado o registro #{total}.")
        if ev["prev_hash"] != prev:
            return falha(ev["seq"], "Encadeamento rompido: o registro não aponta para o anterior.")
        esperado = assinar(ev["seq"], ev["tx_id"], ev["evento"], ev["dados"], ev["prev_hash"], ev["created_at"])
        if not hmac.compare_digest(esperado, ev["hash"]):
            return falha(ev["seq"], "Assinatura inválida: o conteúdo do registro foi alterado.")
        eventos.setdefault(ev["tx_id"], {})[ev["evento"]] = ev
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

    return {"integro": True, "total_eventos": total, "head_hash": prev,
            "falha": None, "verificado_em": agora()}


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


def _decidir(req: DecisionRequest, aprovar: bool) -> dict[str, Any]:
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
            "operador": req.operator_name,
            "justificativa": req.notes,
            "violacoes_reconhecidas": sorted(codigos & set(req.acknowledged_violations)),
            "status_anterior": tx["status"],
            "status": novo_status.value,
        }, decided_at)
        conn.execute(
            "UPDATE transacoes SET status = ?, decisao_id = ?, operador = ?, justificativa = ?, "
            "decided_at = ?, proof_hash = ? WHERE tx_id = ?",
            (novo_status.value, decisao_id, req.operator_name, req.notes,
             decided_at, evento["hash"], tx["tx_id"]),
        )

    return {
        "transaction_id": req.transaction_id,
        "status": novo_status.value,
        "juizo_humano": {
            "operator": req.operator_name,
            "justification": req.notes,
            "acknowledged_violations": sorted(codigos & set(req.acknowledged_violations)),
            "signed_at": decided_at,
        },
        ("selo_calice" if aprovar else "registro_rejeicao"): {
            "seal_id": decisao_id,
            "proof_hash": evento["hash"],
            "ledger_seq": evento["seq"],
            "padrao": PADRAO_SELO,
        },
    }


@app.post("/api/v1/seal")
def seal(req: DecisionRequest) -> dict[str, Any]:
    return _decidir(req, aprovar=True)


@app.post("/api/v1/reject")
def reject(req: DecisionRequest) -> dict[str, Any]:
    return _decidir(req, aprovar=False)


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
            "SELECT seq, evento, prev_hash, hash, created_at FROM ledger WHERE tx_id = ? ORDER BY seq",
            (tx_id,)).fetchall()
    d = serializar(tx, com_conteudo=True)
    d["ledger"] = [dict(e) for e in eventos]
    d["limiar_confianca"] = settings.confidence_threshold
    return d


@app.get("/api/v1/ledger/verify")
def verificar() -> dict[str, Any]:
    with leitura() as conn:
        return verificar_ledger(conn)


@app.get("/api/v1/health")
def health() -> dict[str, Any]:
    return {
        "status": "ok",
        "versao": app.version,
        "chave_desenvolvimento": settings.dev_key,
        "limiar_confianca": settings.confidence_threshold,
        "regras": [r.__name__ for r in REGRAS],
        "padrao": PADRAO_SELO,
    }


@app.get("/", include_in_schema=False)
def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")
