import asyncio
import json
import sqlite3
import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import main  # noqa: E402
import verificar_publico  # noqa: E402

RISCO = {"document_id": "DOC-1", "content": "Liberação de pagamento ao fornecedor.",
         "liability_clause": False, "confidence_score": 0.40}
CONFORME = {**RISCO, "document_id": "DOC-2", "liability_clause": True, "confidence_score": 0.95}


SENHA = "senha-de-teste-longa"


@pytest.fixture
def anonimo(tmp_path, monkeypatch):
    monkeypatch.setenv("CALICE_DB_PATH", str(tmp_path / "teste.db"))
    monkeypatch.setenv("CALICE_SIGNING_KEY", "chave-de-teste")
    with TestClient(main.app) as c:
        main.criar_operador("marina", "Operadora Teste", SENHA)
        yield c


@pytest.fixture
def client(anonimo):
    """Cliente já autenticado como a operadora `marina`."""
    anonimo.headers["Authorization"] = f"Bearer {entrar(anonimo)}"
    return anonimo


def entrar(client, login="marina", senha=SENHA) -> str:
    r = client.post("/api/v1/auth/login", json={"login": login, "password": senha})
    assert r.status_code == 200, r.text
    return r.json()["token"]


def bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def decisao(tx_id: str, **extra) -> dict:
    return {"transaction_id": tx_id, "notes": "Revisado contra o contrato original.", **extra}


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


# ── Assinatura pública (Ed25519) ──────────────────────────────────────────

def selar_varias(client, n: int = 2) -> list[dict]:
    selos = []
    for _ in range(n):
        tx = interceptar(client)
        r = client.post("/api/v1/seal", json=decisao(tx["transaction_id"]))
        selos.append(r.json())
    return selos


def test_exportacao_verifica_so_com_a_chave_publica(client):
    selar_varias(client)
    pub = client.get("/api/v1/ledger/public-key").json()
    assert pub["algoritmo"] == "Ed25519" and len(pub["hex"]) == 64
    export = client.get("/api/v1/ledger/export").json()
    v = verificar_publico.verificar_documento(export, pub["hex"])
    assert v["integro"] is True and v["chave_confiavel"] is True
    assert v["total_eventos"] == 4
    assert v["head_hash"] == client.get("/api/v1/ledger/verify").json()["head_hash"]


def test_selo_traz_assinatura_e_prova_verificavel(client):
    selo = selar_varias(client, 1)[0]
    s = selo["selo_calice"]
    assert s["chave_publica"]["hex"] == client.get("/api/v1/ledger/public-key").json()["hex"]
    prova = client.get(f"/api/v1/transactions/{selo['transaction_id']}/proof").json()
    assert [r["evento"] for r in prova["registros"]] == ["INTERCEPTACAO", "CHANCELA"]
    assert prova["registros"][-1]["hash"] == s["proof_hash"]
    assert prova["registros"][-1]["assinatura"] == s["assinatura"]
    assert verificar_publico.verificar_documento(prova, s["chave_publica"]["hex"])["integro"] is True


def test_prova_de_transacao_inexistente_retorna_404(client):
    assert client.get("/api/v1/transactions/TX-NAO-EXISTE/proof").status_code == 404


@pytest.mark.parametrize("campo,valor", [
    ("dados", '{"operador":"Outra Pessoa"}'),
    ("created_at", "2000-01-01T00:00:00.000+00:00"),
    ("hash", "f" * 64),
])
def test_exportacao_adulterada_falha_na_verificacao_publica(client, campo, valor):
    selar_varias(client, 1)
    export = client.get("/api/v1/ledger/export").json()
    export["registros"][1][campo] = valor
    v = verificar_publico.verificar_documento(export, export["chave_publica"]["hex"])
    assert v["integro"] is False and v["falha"]["seq"] == 2


def test_registros_removidos_ou_reordenados_sao_detectados(client):
    selar_varias(client)
    export = client.get("/api/v1/ledger/export").json()
    pub = export["chave_publica"]["hex"]
    sem_um = {**export, "registros": export["registros"][:1] + export["registros"][2:]}
    assert verificar_publico.verificar_documento(sem_um, pub)["falha"]["seq"] == 3
    trocados = {**export, "registros": [export["registros"][1], export["registros"][0], *export["registros"][2:]]}
    assert verificar_publico.verificar_documento(trocados, pub)["integro"] is False


def test_chave_publica_errada_nao_confere(client):
    selar_varias(client, 1)
    export = client.get("/api/v1/ledger/export").json()
    outra = main.carregar_ed25519(b"outra-chave").public_key().public_bytes(
        main.Encoding.Raw, main.PublicFormat.Raw).hex()
    v = verificar_publico.verificar_documento(export, outra)
    assert v["integro"] is False and v["falha"]["seq"] == 1


def test_sem_chave_explicita_a_verificacao_nao_e_confiavel(client):
    selar_varias(client, 1)
    v = verificar_publico.verificar_documento(client.get("/api/v1/ledger/export").json())
    assert v["integro"] is True and v["chave_confiavel"] is False


def test_verify_interno_detecta_assinatura_ed25519_adulterada(client):
    selar_varias(client, 1)
    db = sqlite3.connect(main.settings.db_path)
    db.execute("DROP TRIGGER ledger_sem_update")
    db.execute("UPDATE ledger SET assinatura = ? WHERE seq = 2", ("00" * 64,))
    db.commit()
    db.close()
    v = client.get("/api/v1/ledger/verify").json()
    assert v["integro"] is False and v["falha"]["seq"] == 2


def test_semente_explicita_define_a_chave(tmp_path, monkeypatch):
    monkeypatch.setenv("CALICE_DB_PATH", str(tmp_path / "semente.db"))
    monkeypatch.setenv("CALICE_SIGNING_KEY", "chave-de-teste")
    monkeypatch.setenv("CALICE_ED25519_SEED", "11" * 32)
    esperado = main.carregar_ed25519(b"irrelevante").public_key().public_bytes(
        main.Encoding.Raw, main.PublicFormat.Raw).hex()
    with TestClient(main.app) as c:
        assert c.get("/api/v1/ledger/public-key").json()["hex"] == esperado


def test_banco_legado_ganha_coluna_e_segue_integro(tmp_path, monkeypatch):
    caminho = tmp_path / "legado.db"
    monkeypatch.setenv("CALICE_DB_PATH", str(caminho))
    monkeypatch.setenv("CALICE_SIGNING_KEY", "chave-de-teste")
    main.settings = main.load_settings()
    dados = main.canonico({"content_sha256": main.sha256_hex("antigo"), "status": "PRONTO_PARA_CHANCELA"})
    criado = "2026-09-28T00:00:00.000+00:00"
    digest = main.assinar(1, "TX-LEGADO", "INTERCEPTACAO", dados, main.GENESIS_HASH, criado)
    with sqlite3.connect(caminho) as db:  # esquema anterior, sem a coluna `assinatura`
        db.executescript(main.SCHEMA.replace(
            ",\n    assinatura TEXT  -- Ed25519 (hex); NULL em registros anteriores à assinatura pública", ""))
        db.execute("INSERT INTO transacoes (tx_id, document_id, content, liability_clause, confidence_score, "
                   "status, violations, created_at) VALUES ('TX-LEGADO', 'D', 'antigo', 1, 0.9, "
                   "'PRONTO_PARA_CHANCELA', '[]', ?)", (criado,))
        db.execute("INSERT INTO ledger (seq, tx_id, evento, dados, prev_hash, hash, created_at) "
                   "VALUES (1, 'TX-LEGADO', 'INTERCEPTACAO', ?, ?, ?, ?)", (dados, main.GENESIS_HASH, digest, criado))
    with TestClient(main.app) as c:
        novo = interceptar(c)
        assert novo["ledger"]["prev_hash"] == digest and novo["ledger"]["assinatura"]
        assert c.get("/api/v1/ledger/verify").json()["integro"] is True
        v = verificar_publico.verificar_documento(c.get("/api/v1/ledger/export").json())
        assert v["integro"] is False and v["falha"]["seq"] == 1
        assert "sem assinatura" in v["falha"]["motivo"]


def test_verificador_publico_por_linha_de_comando(client, tmp_path, capsys):
    selar_varias(client, 1)
    arquivo = tmp_path / "livro.json"
    arquivo.write_text(client.get("/api/v1/ledger/export").text, encoding="utf-8")
    pub = client.get("/api/v1/ledger/public-key").json()["hex"]
    assert verificar_publico.main([str(arquivo), "--chave", pub]) == 0
    assert verificar_publico.main([str(arquivo), "--chave", "ab" * 32]) == 1


# ── Autenticação do operador ──────────────────────────────────────────────

@pytest.mark.parametrize("rota", ["/api/v1/seal", "/api/v1/reject"])
def test_decisao_sem_login_e_recusada(anonimo, rota):
    tx = interceptar(anonimo)
    r = anonimo.post(rota, json=decisao(tx["transaction_id"]))
    assert r.status_code == 401
    assert r.headers["www-authenticate"] == "Bearer"
    assert anonimo.get(f"/api/v1/transactions/{tx['transaction_id']}").json()["status"] == "PRONTO_PARA_CHANCELA"


def test_token_inventado_e_recusado(anonimo):
    tx = interceptar(anonimo)
    r = anonimo.post("/api/v1/seal", json=decisao(tx["transaction_id"]), headers=bearer("inventado"))
    assert r.status_code == 401


@pytest.mark.parametrize("login,senha", [("marina", "senha-errada-123"), ("ninguem", SENHA)])
def test_login_invalido_nao_revela_o_motivo(anonimo, login, senha):
    r = anonimo.post("/api/v1/auth/login", json={"login": login, "password": senha})
    assert r.status_code == 401
    assert r.json()["detail"] == "Login ou senha inválidos."


def test_login_devolve_o_operador(anonimo):
    r = anonimo.post("/api/v1/auth/login", json={"login": "  MARINA ", "password": SENHA})
    assert r.status_code == 200
    assert r.json()["operador"] == {"login": "marina", "nome": "Operadora Teste"}
    assert anonimo.get("/api/v1/auth/me", headers=bearer(r.json()["token"])).json()["login"] == "marina"


def test_operador_vem_da_sessao_e_nao_do_corpo(client):
    tx = interceptar(client)
    r = client.post("/api/v1/seal", json=decisao(tx["transaction_id"], operator_name="Diretor Presidente"))
    assert r.status_code == 200
    assert r.json()["juizo_humano"]["operator"] == "Operadora Teste"
    assert r.json()["juizo_humano"]["operator_login"] == "marina"
    assert client.get(f"/api/v1/transactions/{tx['transaction_id']}").json()["decisao"]["operador"] == "Operadora Teste"


def test_livro_registra_o_login_do_operador(client):
    tx = interceptar(client)
    client.post("/api/v1/reject", json=decisao(tx["transaction_id"]))
    with sqlite3.connect(main.settings.db_path) as db:
        dados = db.execute("SELECT dados FROM ledger WHERE evento = 'REJEICAO'").fetchone()[0]
    assert '"operador_login":"marina"' in dados
    assert client.get("/api/v1/ledger/verify").json()["integro"] is True


def test_logout_invalida_o_token(anonimo):
    token = entrar(anonimo)
    assert anonimo.post("/api/v1/auth/logout", headers=bearer(token)).status_code == 204
    assert anonimo.get("/api/v1/auth/me", headers=bearer(token)).status_code == 401


def test_sessao_expirada_e_recusada(anonimo):
    token = entrar(anonimo)
    with sqlite3.connect(main.settings.db_path) as db:
        db.execute("UPDATE sessoes SET expira_em = '2000-01-01T00:00:00.000+00:00'")
    assert anonimo.get("/api/v1/auth/me", headers=bearer(token)).status_code == 401


def test_operador_desativado_perde_acesso(anonimo):
    token = entrar(anonimo)
    main.definir_ativo("marina", False)
    assert anonimo.get("/api/v1/auth/me", headers=bearer(token)).status_code == 401
    assert anonimo.post("/api/v1/auth/login", json={"login": "marina", "password": SENHA}).status_code == 401
    main.definir_ativo("marina", True)
    entrar(anonimo)


def test_troca_de_senha_encerra_sessoes(anonimo):
    token = entrar(anonimo)
    main.definir_senha("marina", "outra-senha-bem-longa")
    assert anonimo.get("/api/v1/auth/me", headers=bearer(token)).status_code == 401
    entrar(anonimo, senha="outra-senha-bem-longa")


def test_banco_nao_guarda_senha_nem_token_em_claro(anonimo):
    token = entrar(anonimo)
    with sqlite3.connect(main.settings.db_path) as db:
        despejo = "\n".join(db.iterdump())
    assert SENHA not in despejo and token not in despejo


@pytest.mark.parametrize("login,nome,senha", [
    ("marina", "Outra Marina", SENHA),     # login repetido
    ("x", "Nome Válido", SENHA),           # login curto
    ("joao", "João Silva", "curta"),       # senha curta
])
def test_criacao_de_operador_valida_dados(anonimo, login, nome, senha):
    with pytest.raises(ValueError):
        main.criar_operador(login, nome, senha)


def test_cli_cria_operador(anonimo, monkeypatch, capsys):
    monkeypatch.setattr("getpass.getpass", lambda _: "senha-do-joao-123")
    assert main.cli(["operador", "criar", "joao", "João Silva"]) == 0
    assert "joao" in capsys.readouterr().out
    entrar(anonimo, "joao", "senha-do-joao-123")


# ── Janelas temporais e plantão ──────────────────────────────────────────

@pytest.fixture
def plantao(anonimo):
    """Duas operadoras: `marina` (plantonista) e `joana` (outra operadora)."""
    main.criar_operador("joana", "Outra Operadora", SENHA)
    return anonimo


def com_plantao(risco="HIGH", **extra) -> dict:
    return {**CONFORME, "risk_level": risco, "designated_operator": "marina", **extra}


def test_intercept_registra_risco_plantonista_e_prazo(plantao):
    tx = interceptar(plantao, com_plantao())
    assert tx["janela"]["risco"] == "HIGH"
    assert tx["janela"]["operador_de_plantao"] == "marina"
    assert tx["janela"]["janela_segundos"] == main.settings.janelas["HIGH"]
    dados = plantao.get(f"/api/v1/transactions/{tx['transaction_id']}").json()
    assert dados["janela"]["prazo"] == tx["janela"]["prazo"]
    assert dados["janela"]["prazo_esgotado_em"] is None


def test_risco_padrao_e_medium_sem_plantonista(client):
    tx = interceptar(client)
    assert tx["janela"]["risco"] == "MEDIUM"
    assert tx["janela"]["operador_de_plantao"] is None


def test_plantonista_inexistente_e_recusado(plantao):
    r = plantao.post("/api/v1/intercept", json=com_plantao(designated_operator="ninguem"))
    assert r.status_code == 422


def test_risco_invalido_e_recusado(plantao):
    assert plantao.post("/api/v1/intercept", json=com_plantao(risco="EXTREMO")).status_code == 422


def test_dentro_da_janela_so_o_plantonista_decide(plantao):
    tx = interceptar(plantao, com_plantao())
    outra = plantao.post("/api/v1/seal", json=decisao(tx["transaction_id"]), headers=bearer(entrar(plantao, "joana")))
    assert outra.status_code == 403
    assert outra.json()["detail"]["operador_de_plantao"] == "marina"
    dona = plantao.post("/api/v1/seal", json=decisao(tx["transaction_id"]), headers=bearer(entrar(plantao)))
    assert dona.status_code == 200, dona.text


def test_prazo_esgotado_nao_aprova_e_libera_outros_operadores(plantao, monkeypatch):
    monkeypatch.setitem(main.settings.janelas, "HIGH", 0)
    tx = interceptar(plantao, com_plantao())

    assert main.varrer_prazos() == 1
    assert main.varrer_prazos() == 0  # registrado uma vez só
    dados = plantao.get(f"/api/v1/transactions/{tx['transaction_id']}").json()
    assert dados["status"] == "PRONTO_PARA_CHANCELA"  # o silêncio não aprova
    assert dados["decisao"] is None
    assert [e["evento"] for e in dados["ledger"]] == ["INTERCEPTACAO", "PRAZO_ESGOTADO"]

    r = plantao.post("/api/v1/seal", json=decisao(tx["transaction_id"]), headers=bearer(entrar(plantao, "joana")))
    assert r.status_code == 200, r.text
    assert r.json()["juizo_humano"]["operator_login"] == "joana"
    assert plantao.get("/api/v1/ledger/verify").json()["integro"] is True


def test_decisao_apos_prazo_registra_esgotamento_antes(plantao, monkeypatch):
    """Sem varredura, a própria decisão registra o esgotamento antes da chancela."""
    monkeypatch.setitem(main.settings.janelas, "LOW", 0)
    tx = interceptar(plantao, com_plantao("LOW"))
    r = plantao.post("/api/v1/reject", json=decisao(tx["transaction_id"]), headers=bearer(entrar(plantao, "joana")))
    assert r.status_code == 200, r.text
    eventos = plantao.get(f"/api/v1/transactions/{tx['transaction_id']}").json()["ledger"]
    assert [e["evento"] for e in eventos] == ["INTERCEPTACAO", "PRAZO_ESGOTADO", "REJEICAO"]


def test_varredura_ignora_transacoes_decididas(plantao, monkeypatch):
    monkeypatch.setitem(main.settings.janelas, "HIGH", 0)
    tx = interceptar(plantao, com_plantao())
    main.varrer_prazos()
    plantao.post("/api/v1/seal", json=decisao(tx["transaction_id"]), headers=bearer(entrar(plantao)))
    interceptar(plantao, com_plantao())
    assert main.varrer_prazos() == 1  # só a nova


def test_janelas_configuraveis_por_ambiente(tmp_path, monkeypatch):
    monkeypatch.setenv("CALICE_JANELA_HIGH", "42")
    assert main.load_settings().janelas["HIGH"] == 42


def test_banco_legado_ganha_colunas_de_janela(tmp_path, monkeypatch):
    db = tmp_path / "legado.db"
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE transacoes (tx_id TEXT PRIMARY KEY, document_id TEXT NOT NULL, "
                 "content TEXT NOT NULL, liability_clause INTEGER NOT NULL, confidence_score REAL NOT NULL, "
                 "status TEXT NOT NULL, violations TEXT NOT NULL, created_at TEXT NOT NULL, decisao_id TEXT UNIQUE, "
                 "operador TEXT, justificativa TEXT, decided_at TEXT, proof_hash TEXT UNIQUE)")
    conn.commit()
    conn.close()
    monkeypatch.setenv("CALICE_DB_PATH", str(db))
    monkeypatch.setenv("CALICE_SIGNING_KEY", "chave-de-teste")
    with TestClient(main.app) as c:
        assert main.varrer_prazos() == 0
        assert interceptar(c)["janela"]["risco"] == "MEDIUM"


# ── Sincronização entre janelas ───────────────────────────────────────────

TOPICO = "contrato-fornecedor-42"


def chancelada(client) -> dict:
    tx = interceptar(client)
    r = client.post("/api/v1/seal", json=decisao(tx["transaction_id"]))
    assert r.status_code == 200, r.text
    return r.json()


def sincronizar(client, tx_id: str, janela="janela-A", dados=None, topico=TOPICO):
    return client.post(f"/api/v1/topics/{topico}/outcomes", json={
        "transaction_id": tx_id, "janela": janela, "dados": dados or {"prazo_dias": 30}})


def test_topico_sem_historico_devolve_aviso(anonimo):
    r = anonimo.get(f"/api/v1/topics/{TOPICO}/context").json()
    assert r["itens"] == []
    assert r["contexto"] == "Nenhum contexto prévio registrado para este tópico."


def test_janela_b_recebe_o_que_a_janela_a_chancelou(client):
    a = chancelada(client)
    b = chancelada(client)
    ra = sincronizar(client, a["transaction_id"], "janela-A", {"prazo_dias": 30, "multa": "2%"})
    assert ra.status_code == 201, ra.text
    assert sincronizar(client, b["transaction_id"], "janela-C", {"índice": "IPCA"}).status_code == 201

    r = client.get(f"/api/v1/topics/{TOPICO}/context").json()
    assert [i["janela"] for i in r["itens"]] == ["janela-A", "janela-C"]
    # A certidão é o selo real da chancela, não um valor informado pelo cliente.
    assert r["itens"][0]["hash_certidao"] == a["selo_calice"]["proof_hash"]
    linhas = r["contexto"].splitlines()
    assert linhas[0] == "FATOS E DELIBERAÇÕES ANTERIORES CHANCELADOS:"
    assert "Origem: janela-A" in linhas[1] and a["selo_calice"]["proof_hash"][:12] in linhas[1]
    assert '{"multa":"2%","prazo_dias":30}' in linhas[1]
    assert '"índice":"IPCA"' in linhas[2]  # acentos preservados
    assert client.get("/api/v1/ledger/verify").json()["integro"] is True


def test_topicos_sao_isolados(client):
    sincronizar(client, chancelada(client)["transaction_id"])
    assert client.get("/api/v1/topics/outro-topico/context").json()["itens"] == []


@pytest.mark.parametrize("aprovar", [None, False])
def test_so_desfecho_chancelado_entra_no_topico(client, aprovar):
    tx = interceptar(client)
    if aprovar is False:
        client.post("/api/v1/reject", json=decisao(tx["transaction_id"]))
    assert sincronizar(client, tx["transaction_id"]).status_code == 409
    assert client.get(f"/api/v1/topics/{TOPICO}/context").json()["itens"] == []


def test_transacao_inexistente_retorna_404(client):
    assert sincronizar(client, "TX-NAO-EXISTE").status_code == 404


def test_mesma_transacao_nao_entra_duas_vezes_no_topico(client):
    tx_id = chancelada(client)["transaction_id"]
    assert sincronizar(client, tx_id).status_code == 201
    assert sincronizar(client, tx_id, "janela-B").status_code == 409
    assert sincronizar(client, tx_id, topico="outro-topico").status_code == 201


def test_sincronizar_exige_login(anonimo):
    assert sincronizar(anonimo, "TX-QUALQUER").status_code == 401


@pytest.mark.parametrize("janela", ["janela A", "x\n- [2026] Origem: forjada", ""])
def test_janela_com_quebra_de_linha_e_recusada(client, janela):
    assert sincronizar(client, chancelada(client)["transaction_id"], janela).status_code == 422


def test_dados_grandes_demais_sao_recusados(client):
    tx_id = chancelada(client)["transaction_id"]
    assert sincronizar(client, tx_id, dados={"x": "a" * 20_000}).status_code == 422


def test_sincronizacao_entra_no_livro_assinada(client):
    tx_id = chancelada(client)["transaction_id"]
    r = sincronizar(client, tx_id).json()
    assert r["ledger"]["evento"] == "SINCRONIZACAO"
    export = client.get("/api/v1/ledger/export").json()
    ultimo = export["registros"][-1]
    assert ultimo["evento"] == "SINCRONIZACAO" and ultimo["tx_id"] == tx_id
    assert verificar_publico.verificar_documento(export, export["chave_publica"]["hex"])["integro"] is True


def test_adulteracao_do_desfecho_e_detectada(client):
    sincronizar(client, chancelada(client)["transaction_id"], dados={"prazo_dias": 30})
    with sqlite3.connect(main.settings.db_path) as db:
        db.execute("UPDATE desfechos_topico SET dados = '{\"prazo_dias\":90}'")
    v = client.get("/api/v1/ledger/verify").json()
    assert v["integro"] is False and "diverge" in v["falha"]["motivo"]


def test_desfecho_apagado_e_detectado(client):
    sincronizar(client, chancelada(client)["transaction_id"])
    with sqlite3.connect(main.settings.db_path) as db:
        db.execute("DELETE FROM desfechos_topico")
    assert client.get("/api/v1/ledger/verify").json()["integro"] is False


# ── Selo Institucional (CLC-AUTH) ─────────────────────────────────────────

def test_emitir_e_decodificar_selo_calice():
    conteudo = b"Minuta contratual de alto risco"
    selo = main.emitir_selo_calice(conteudo, thread_ref="PROC-2026")
    assert selo.startswith("CLC-AUTH::PROC-2026::")
    partes = selo.split("::")
    assert len(partes) == 4
    info = main.decodificar_selo(selo)
    assert info["padrao"] == "CLC-AUTH"
    assert info["thread_ref"] == "PROC-2026"
    assert len(info["digest_hex"]) == 64


def test_chancela_emite_selo_institucional(client):
    tx_id = interceptar(client)["transaction_id"]
    r = client.post("/api/v1/seal", json=decisao(tx_id, acknowledged_violations=["LACUNA_JURIDICA"]))
    assert r.status_code == 200
    selo_inst = r.json()["selo_calice"]["selo_institucional"]
    assert selo_inst.startswith(f"CLC-AUTH::{tx_id}::")

    # Confere na rota de detalhe da transação
    det = client.get(f"/api/v1/transactions/{tx_id}").json()
    assert det["decisao"]["selo_institucional"] == selo_inst

    # Decodifica pela rota pública de validação de selo
    dec = client.get("/api/v1/seal/decode", params={"selo": selo_inst})
    assert dec.status_code == 200
    assert dec.json()["valido"] is True
    assert dec.json()["detalhes"]["thread_ref"] == tx_id


def test_decodificacao_de_selo_invalido_rejeita(client):
    r = client.get("/api/v1/seal/decode", params={"selo": "SELO_INVALIDO_SEM_FORMATO"})
    assert r.status_code == 400


# ── Políticas de Cliente e Decurso de Prazo (SLA) ─────────────────────────

def test_consultar_politica_padrao_cliente(client):
    r = client.get("/api/v1/policies/CLI_1029")
    assert r.status_code == 200
    dados = r.json()
    assert dados["politica_cliente_id"] == "CLI_1029"
    assert "FINANCEIRO_PIX" in dados["regras_de_operacao"]
    assert dados["regras_de_operacao"]["FINANCEIRO_PIX"]["prazo_segundos"] == 120
    assert dados["regras_de_operacao"]["FINANCEIRO_PIX"]["acao_no_esgotamento"] == "CANCELAMENTO_AUTOMATICO"


def test_cadastrar_nova_politica_cliente(client):
    payload = {
        "politica_cliente_id": "CLI_EMPRESA_X",
        "regras_de_operacao": {
            "PAGAMENTO_FORNECEDOR": {
                "limiar_corte": 0.50,
                "prazo_segundos": 60,
                "acao_no_esgotamento": "CANCELAMENTO_AUTOMATICO",
            }
        },
    }
    r = client.post("/api/v1/policies", json=payload)
    assert r.status_code == 201
    consulta = client.get("/api/v1/policies/CLI_EMPRESA_X").json()
    assert consulta["regras_de_operacao"]["PAGAMENTO_FORNECEDOR"]["prazo_segundos"] == 60


def test_interceptacao_amarra_prazo_limite_e_tolerancia(client):
    payload = {
        **CONFORME,
        "document_id": "PIX-1029-A",
        "politica_cliente_id": "CLI_1029",
        "tipo_operacao": "FINANCEIRO_PIX",
        "confidence_score": 0.88,
    }
    r = client.post("/api/v1/intercept", json=payload)
    assert r.status_code == 201
    dados = r.json()
    assert dados["janela"]["janela_segundos"] == 120
    assert dados["janela"]["acao_no_esgotamento"] == "CANCELAMENTO_AUTOMATICO"
    assert "prazo_limite_utc" in dados["ledger"]["dados"]


def test_decurso_de_prazo_cancela_automaticamente(client):
    payload = {
        **CONFORME,
        "document_id": "PIX-TIMEOUT-TEST",
        "politica_cliente_id": "CLI_1029",
        "tipo_operacao": "FINANCEIRO_PIX",
    }
    tx_id = client.post("/api/v1/intercept", json=payload).json()["transaction_id"]

    # Simula decurso forçando o prazo no passado
    with sqlite3.connect(main.settings.db_path) as db:
        passado = "2020-01-01T00:00:00.000+00:00"
        db.execute("UPDATE transacoes SET prazo = ? WHERE tx_id = ?", (passado, tx_id))

    # Executa varredura de decurso
    n = main.varrer_prazos()
    assert n >= 1

    # Verifica status e livro
    detalhe = client.get(f"/api/v1/transactions/{tx_id}").json()
    assert detalhe["status"] == "CANCELADO_POR_TIMEOUT"
    assert detalhe["decisao"]["operador"] == "SISTEMA (AUTOMAÇÃO SLA)"

    # Livro-razão deve permanecer 100% íntegro
    v = client.get("/api/v1/ledger/verify").json()
    assert v["integro"] is True


def test_prazo_customizado_no_payload_prevalece(client):
    payload = {
        **CONFORME,
        "document_id": "CUSTOM-PRAZO-01",
        "confidence_score": 0.95,
        "prazo_customizado_segundos": 450,
    }
    r = client.post("/api/v1/intercept", json=payload)
    assert r.status_code == 201
    dados = r.json()
    assert dados["janela"]["prazo_segundos"] == 450
    bloco_ledger = json.loads(dados["ledger"]["dados"])
    assert bloco_ledger["prazo_segundos"] == 450
    assert "prazo_limite_utc" in bloco_ledger


def test_calculo_tempo_por_confianca(client):
    # Teste unitário da função direta
    assert main.calcular_tempo_por_confianca(0.95) == 7200
    assert main.calcular_tempo_por_confianca(0.85) == 7200
    assert main.calcular_tempo_por_confianca(0.70) == 1800
    assert main.calcular_tempo_por_confianca(0.50) == 1800
    assert main.calcular_tempo_por_confianca(0.40) == 300
    assert main.calcular_tempo_por_confianca(0.10) == 300

    # Teste via API sem prazo customizado e sem politica_cliente_id
    # Confiança baixa (< 0.50) => 300s
    p_baixa = {**CONFORME, "document_id": "CONF-BAIXA", "confidence_score": 0.45}
    r_baixa = client.post("/api/v1/intercept", json=p_baixa).json()
    assert r_baixa["janela"]["prazo_segundos"] == 300
    assert json.loads(r_baixa["ledger"]["dados"])["prazo_segundos"] == 300

    # Confiança média (0.75) => 1800s
    p_media = {**CONFORME, "document_id": "CONF-MEDIA", "confidence_score": 0.75}
    r_media = client.post("/api/v1/intercept", json=p_media).json()
    assert r_media["janela"]["prazo_segundos"] == 1800

    # Confiança alta (0.90) => 7200s
    p_alta = {**CONFORME, "document_id": "CONF-ALTA", "confidence_score": 0.90}
    r_alta = client.post("/api/v1/intercept", json=p_alta).json()
    assert r_alta["janela"]["prazo_segundos"] == 7200


def test_processar_interceptacao_helper():
    # Com prazo customizado
    ev1 = {"score": 0.40, "tipo_operacao": "TESTE", "prazo_customizado_segundos": 60}
    bloco1 = main.processar_interceptacao(ev1)
    assert bloco1["prazo_segundos"] == 60
    assert "prazo_limite_utc" in bloco1

    # Sem prazo customizado, fallback para confiança
    ev2 = {"score": 0.92, "tipo_operacao": "TESTE"}
    bloco2 = main.processar_interceptacao(ev2)
    assert bloco2["prazo_segundos"] == 7200


def test_calice_engine_avaliar_stream():
    engine = main.calice_engine

    # Texto seguro com cláusula
    score_ok, viol_ok = engine.avaliar_stream("Minuta de contrato contendo cláusula de responsabilidade expressa.")
    assert score_ok >= 0.85
    assert viol_ok is None

    # Gatilho crítico: sem cláusula
    score_viol, viol_cod = engine.avaliar_stream("Transferência bancária sem cláusula de garantia prévia.")
    assert score_viol < 0.85
    assert viol_cod == "LACUNA_JURIDICA"

    # Termo de dispersão
    score_disp, viol_disp = engine.avaliar_stream("Valor estimado sem base probatória conclusiva.")
    assert score_disp < 0.85


def test_executar_geracao_sob_custodia_intercepta_ao_vivo(client):
    # Executa a geração que aciona corte ao vivo no chunk de risco
    tx = main.executar_geracao_sob_custodia_calice(
        prompt_estatistico="Elabore ordem de transferência emergencial sem garantia expressa.",
        limiar_corte=0.85,
        prazo_sla_segundos=1200,
        documento_id="DOC-STREAM-TEST",
    )
    assert "transaction_id" in tx
    assert tx["status"] == "FATOR_DE_PAUSA_ATIVADO"
    assert tx["janela"]["prazo_segundos"] == 1200
    assert any(v["codigo"] in ("CONFIANCA_BAIXA", "LACUNA_JURIDICA") for v in tx["violations"])

    # Verifica integridade do livro-razão após corte ao vivo
    verificacao = client.get("/api/v1/ledger/verify").json()
    assert verificacao["integro"] is True


def test_api_stream_generate_intercepta(client):
    payload = {
        "prompt": "Gerar parecer financeiro emergencial sem cláusula",
        "limiar_corte": 0.80,
        "prazo_sla_segundos": 600,
        "documento_id": "DOC-STREAM-API",
    }
    r = client.post("/api/v1/stream/generate", json=payload)
    assert r.status_code == 200
    dados = r.json()
    assert dados["status"] == "FATOR_DE_PAUSA_ATIVADO"
    assert dados["janela"]["prazo_segundos"] == 600


def test_calcular_demanda():
    # Amostras conformes
    res1 = main.calcular_demanda([0.88, 0.92, 0.85, 0.90])
    assert res1["verificado"] is True
    assert res1["status_demanda"] == "CONFORME"
    assert res1["total_amostras"] == 4
    assert res1["media_confianca"] >= 0.85

    # Amostras com alta dispersão / baixa média
    res2 = main.calcular_demanda([0.40, 0.50, 0.35])
    assert res2["status_demanda"] == "DISPERSAO_ALTA"
    assert res2["media_confianca"] < 0.85


@pytest.mark.anyio
async def test_bancada_concorrente():
    from bancada_concorrente import CaliceLedgerConcorrente, disparar_evento_teste
    ledger = CaliceLedgerConcorrente(limiar_confianca=0.85)
    tarefas = [disparar_evento_teste(ledger, f"CLIENTE-{i}", i + 1) for i in range(10)]
    resultados = await asyncio.gather(*tarefas)

    assert len(resultados) == 10
    assert len(ledger.registos) == 10
    # Verifica que todos os blocos foram selados de 1 a 10 de forma estrita
    blocos = sorted(r["bloco"] for r in ledger.registos)
    assert blocos == list(range(1, 11))
    # Verifica integridade da cadeia de hashes
    for idx in range(1, len(ledger.registos)):
        atual = ledger.registos[idx]
        anterior = ledger.registos[idx - 1]
        assert atual["hash_anterior_completo"] == anterior["hash_completo"]


def test_interceptar_alias_e_payload_portugues(client):
    payload = {
        "documento_id": "DOC-PORTUGUES-001",
        "conteudo_proposto": "Operação financeira de teste com chaves em português",
        "confianca_modelo": 0.92,
        "contem_clausula": True,
        "janela_sla_segundos": 1800,
    }
    r1 = client.post("/api/interceptar", json=payload)
    assert r1.status_code == 201
    d1 = r1.json()
    assert d1["status"] == "PRONTO_PARA_CHANCELA"
    assert d1["janela"]["prazo_segundos"] == 1800

    # Teste no alias /api/v1/interceptar
    payload["documento_id"] = "DOC-PORTUGUES-002"
    payload["confianca_modelo"] = 0.50
    r2 = client.post("/api/v1/interceptar", json=payload)
    assert r2.status_code == 201
    d2 = r2.json()
    assert d2["status"] == "FATOR_DE_PAUSA_ATIVADO"
    assert len(d2["violations"]) > 0


@pytest.mark.anyio
async def test_disparo_concorrente_api(anonimo):
    import httpx

    transport = httpx.ASGITransport(app=main.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        async def disparar(i: int):
            score = 0.45 if i % 2 == 0 else 0.88
            payload = {
                "documento_id": f"DOC-CONCORRENTE-{i:03d}",
                "conteudo_proposto": f"Operação financeira de teste concorrente #{i}",
                "confianca_modelo": score,
                "contem_clausula": True,
                "janela_sla_segundos": 1800,
            }
            res = await client.post("/api/interceptar", json=payload)
            return res

        resps = await asyncio.gather(*(disparar(i) for i in range(1, 11)))
        assert len(resps) == 10
        assert all(r.status_code == 201 for r in resps)
        # Todos os 10 eventos foram registrados no livro-razão
        with main.leitura() as conn:
            txs = conn.execute("SELECT COUNT(*) as c FROM transacoes WHERE document_id LIKE 'DOC-CONCORRENTE-%'").fetchone()
            assert txs["c"] == 10

