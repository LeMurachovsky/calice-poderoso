import sqlite3
import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import main  # noqa: E402

RISCO = {"document_id": "DOC-1", "content": "Liberação de pagamento ao fornecedor.",
         "liability_clause": False, "confidence_score": 0.40}
CONFORME = {**RISCO, "document_id": "DOC-2", "liability_clause": True, "confidence_score": 0.95}


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("CALICE_DB_PATH", str(tmp_path / "teste.db"))
    monkeypatch.setenv("CALICE_SIGNING_KEY", "chave-de-teste")
    with TestClient(main.app) as c:
        yield c


def decisao(tx_id: str, **extra) -> dict:
    return {"transaction_id": tx_id, "operator_name": "Operadora Teste",
            "notes": "Revisado contra o contrato original.", **extra}


def interceptar(client, payload=CONFORME) -> dict:
    r = client.post("/api/v1/intercept", json=payload)
    assert r.status_code == 201, r.text
    return r.json()


# ── Regras ────────────────────────────────────────────────────────────────

def test_proposta_conforme_fica_pronta(client):
    tx = interceptar(client)
    assert tx["status"] == "PRONTO_PARA_CHANCELA"
    assert tx["violations"] == []


def test_proposta_com_risco_ativa_pausa(client):
    tx = interceptar(client, RISCO)
    assert tx["status"] == "FATOR_DE_PAUSA_ATIVADO"
    assert {v["codigo"] for v in tx["violations"]} == {"LACUNA_JURIDICA", "CONFIANCA_BAIXA"}


@pytest.mark.parametrize("score", [-0.1, 1.5])
def test_confianca_fora_do_intervalo_e_recusada(client, score):
    assert client.post("/api/v1/intercept", json={**CONFORME, "confidence_score": score}).status_code == 422


# ── Juízo humano ──────────────────────────────────────────────────────────

def test_chancela_de_pausa_exige_ciencia_de_cada_violacao(client):
    tx = interceptar(client, RISCO)
    r = client.post("/api/v1/seal", json=decisao(tx["transaction_id"], acknowledged_violations=["LACUNA_JURIDICA"]))
    assert r.status_code == 422
    assert r.json()["detail"]["violacoes_sem_ciencia"] == ["CONFIANCA_BAIXA"]

    r = client.post("/api/v1/seal", json=decisao(
        tx["transaction_id"], acknowledged_violations=["LACUNA_JURIDICA", "CONFIANCA_BAIXA"]))
    assert r.status_code == 200
    assert r.json()["status"] == "CHANCELADO_E_CONCLUIDO"


def test_justificativa_so_com_espacos_e_recusada(client):
    tx = interceptar(client)
    r = client.post("/api/v1/seal", json=decisao(tx["transaction_id"], notes="     ok          "))
    assert r.status_code == 422


def test_selo_duplicado_retorna_409(client):
    tx = interceptar(client)
    assert client.post("/api/v1/seal", json=decisao(tx["transaction_id"])).status_code == 200
    assert client.post("/api/v1/seal", json=decisao(tx["transaction_id"])).status_code == 409


def test_rejeitada_nao_pode_ser_chancelada(client):
    tx = interceptar(client, RISCO)
    assert client.post("/api/v1/reject", json=decisao(tx["transaction_id"])).json()["status"] == "REJEITADO"
    assert client.post("/api/v1/seal", json=decisao(tx["transaction_id"])).status_code == 409


def test_chancelas_simultaneas_so_uma_vence(client):
    tx = interceptar(client)
    with ThreadPoolExecutor(max_workers=8) as pool:
        codigos = list(pool.map(
            lambda _: client.post("/api/v1/seal", json=decisao(tx["transaction_id"])).status_code, range(8)))
    assert sorted(codigos) == [200] + [409] * 7


# ── Livro-razão ───────────────────────────────────────────────────────────

def test_cadeia_e_linear_mesmo_sem_selos_entre_eventos(client):
    a = interceptar(client)
    b = interceptar(client)
    assert b["ledger"]["prev_hash"] == a["ledger"]["hash"]
    assert b["ledger"]["seq"] == a["ledger"]["seq"] + 1


def test_payloads_identicos_geram_hashes_distintos(client):
    assert interceptar(client)["hash_intermediario"] != interceptar(client)["hash_intermediario"]


def test_livro_integro_apos_operacoes(client):
    for payload in (RISCO, CONFORME, CONFORME):
        tx = interceptar(client, payload)
        codigos = [v["codigo"] for v in tx["violations"]]
        client.post("/api/v1/seal", json=decisao(tx["transaction_id"], acknowledged_violations=codigos))
    v = client.get("/api/v1/ledger/verify").json()
    assert v["integro"] is True and v["total_eventos"] == 6


def test_trigger_bloqueia_alteracao_direta(client):
    interceptar(client)
    with sqlite3.connect(main.settings.db_path) as db, pytest.raises(sqlite3.DatabaseError):
        db.execute("UPDATE ledger SET dados = '{}'")


def test_adulteracao_do_livro_e_detectada(client):
    tx = interceptar(client)
    client.post("/api/v1/seal", json=decisao(tx["transaction_id"]))
    db = sqlite3.connect(main.settings.db_path)
    db.execute("DROP TRIGGER ledger_sem_update")  # atacante com acesso ao arquivo
    db.execute("UPDATE ledger SET dados = replace(dados, 'Operadora Teste', 'Outra Pessoa') WHERE seq = 2")
    db.commit()
    db.close()
    v = client.get("/api/v1/ledger/verify").json()
    assert v["integro"] is False
    assert v["falha"]["seq"] == 2


def test_adulteracao_da_projecao_e_detectada(client):
    tx = interceptar(client)
    with sqlite3.connect(main.settings.db_path) as db:
        db.execute("UPDATE transacoes SET content = 'Texto trocado' WHERE tx_id = ?", (tx["transaction_id"],))
    assert client.get("/api/v1/ledger/verify").json()["integro"] is False


def test_sem_a_chave_nao_se_recalcula_a_cadeia(client):
    interceptar(client)
    original = main.settings
    main.settings = replace(original, signing_key=b"chave-errada")
    try:
        assert client.get("/api/v1/ledger/verify").json()["integro"] is False
    finally:
        main.settings = original
