import httpx
import json

client = httpx.Client(base_url="http://127.0.0.1:8000")

print("=== 1. INTERCEPTAÇÃO DA PROPOSTA COM JANELA ESPECIFICADA (SELETOR DE ECRÃ) ===")
# Em vez de disparar a rotina automática de fallback de confiança,
# envia explicitamente o parâmetro de tempo escolhido pelo operador no ecrã:
req_data = {
    "document_id": "DOC-ESTATISTICA-VAR",
    "content": "Do ponto de vista atuarial e estatístico rigoroso, a execução solicitada apresenta inconsistências metodológicas severas e premissas mutuamente excludentes sem cláusula de responsabilidade expressa.",
    "liability_clause": False,
    "confidence_score": 0.70,
    "risk_level": "HIGH",
    "designated_operator": "admin",
    "prazo_customizado_segundos": 120  # 2 minutos definidos explicitamente no controle visual
}
r1 = client.post("/api/v1/intercept", json=req_data)
tx = r1.json()
tx_id = tx["transaction_id"]
bloco_intercept = json.loads(tx["ledger"]["dados"])
print(f"Transação criada: {tx_id}")
print(f"Status: {tx['status']}")
print(f"Violações detectadas: {[v['codigo'] for v in tx['violations']]}")
print(f"Prazo Customizado Cravado no Bloco: {bloco_intercept['prazo_segundos']}s")
print(f"Instante Limite Gravado (T_max UTC): {bloco_intercept['prazo_limite_utc']}")
print(f"Janela de Risco: {tx['janela']['risco']} (Plantão: {tx['janela']['operador_de_plantao']})")

print("\n=== 2. AUTENTICAÇÃO DO OPERADOR (SCRYPT + BEARER) ===")
r2 = client.post("/api/v1/auth/login", json={"login": "admin", "password": "admin12345678"})
token = r2.json()["token"]
print(f"Operador autenticado: {r2.json()['operador']['nome']}")
print(f"Token Bearer gerado: {token[:16]}... (guardado apenas como SHA-256)")

print("\n=== 3. CHANCELA HUMANA E EMISSÃO DO SELO INSTITUCIONAL ===")
headers = {"Authorization": f"Bearer {token}"}
seal_payload = {
    "transaction_id": tx_id,
    "notes": "Pagamento auditado e aprovado com base na deliberação diretiva 2026/09.",
    "acknowledged_violations": ["LACUNA_JURIDICA", "CONFIANCA_BAIXA"]
}
r3 = client.post("/api/v1/seal", json=seal_payload, headers=headers)
seal_res = r3.json()
selo_oficial = seal_res["selo_calice"]["selo_institucional"]
proof_hash = seal_res["selo_calice"]["proof_hash"]
print(f"Status final: {seal_res['status']}")
print(f"ID da Decisão: {seal_res['selo_calice']['seal_id']}")
print(f"Selo Institucional Oficial: {selo_oficial}")
print(f"Proof Hash (HMAC): {proof_hash[:20]}...")
print(f"Assinatura Ed25519: {seal_res['selo_calice']['assinatura'][:20]}...")

print("\n=== 4. DECODIFICAÇÃO PERICIAL DO SELO (CLC-AUTH) ===")
r4 = client.get("/api/v1/seal/decode", params={"selo": selo_oficial})
print(json.dumps(r4.json(), indent=2, ensure_ascii=False))

print("\n=== 5. AUDITORIA DE INTEGRIDADE DO LIVRO-RAZÃO ===")
r5 = client.get("/api/v1/ledger/verify")
v = r5.json()
print(f"Livro íntegro: {v['integro']}")
print(f"Total de eventos encadeados: {v['total_eventos']}")
print(f"Head Hash atual: {v['head_hash']}")

print("\n=== 6. VERIFICAÇÃO DE TIMEOUT E LAVRATURA POR INÉRCIA ===")
# Demonstração da função verificar_timeout para operações com SLA (ex.: FINANCEIRO_PIX)
pix_req = {
    "document_id": "PIX-SLA-TEST",
    "content": "Transferência PIX no valor de R$ 50.000,00 sob política CLI_1029.",
    "liability_clause": True,
    "confidence_score": 0.35,
    "politica_cliente_id": "CLI_1029",
    "tipo_operacao": "FINANCEIRO_PIX"
}
r_pix = client.post("/api/v1/intercept", json=pix_req).json()
hash_interceptacao = r_pix["hash_intermediario"]
t_max = r_pix["janela"]["prazo"]
print(f"PIX Interceptado: {r_pix['transaction_id']}")
print(f"Hash da Interceptação: {hash_interceptacao[:20]}...")
print(f"Prazo Limite T_max: {t_max} (SLA: {r_pix['janela']['janela_segundos']}s)")
print(f"Ação no Esgotamento: {r_pix['janela']['acao_no_esgotamento']}")

# Executa verificação de timeout
res_timeout = client.post("/api/v1/timeout/verify", params={
    "hash_interceptacao": hash_interceptacao,
    "t_max": "2020-01-01T00:00:00.000+00:00"  # Simula decurso de prazo
}).json()

bloco = res_timeout.get("bloco_lavrado")
if bloco:
    print(f"\nDecurso de prazo detectado!")
    print(f"Tipo de Evento Lavrado: {bloco['evento']}")
    print(f"Hash do Bloco: {bloco['hash'][:20]}...")
    print(f"Assinatura Ed25519: {bloco['assinatura'][:20]}...")
    print(f"Motivo Registrado: {json.loads(bloco['dados'])['motivo']}")
    print(f"Status Atualizado: {json.loads(bloco['dados'])['status']}")

print("\n=== 7. GERAÇÃO GEMINI SOB CUSTÓDIA DO CÁLICE COM INTERCEPTAÇÃO EM TEMPO REAL ===")
# Dispara a geração sob custódia probatória diretamente pelo endpoint /api/v1/stream/generate
prompt_exemplo = (
    "Do ponto de vista atuarial e estatístico rigoroso, a execução solicitada apresenta "
    "inconsistências metodológicas severas e premissas mutuamente excludentes..."
)
r_stream = client.post("/api/v1/stream/generate", json={
    "prompt": prompt_exemplo,
    "limiar_corte": 0.85,
    "prazo_sla_segundos": 1800,
    "documento_id": "DOC-ESTATISTICA-VAR"
})
dados_corte = r_stream.json()
print(f"Transação Criada no Corte: {dados_corte.get('transaction_id')}")
print(f"Status Congelado na Bancada: {dados_corte.get('status')}")
print(f"Violações Detectadas no Streaming: {[v['codigo'] for v in dados_corte.get('violations', [])]}")
print(f"Prazo SLA Concedido: {dados_corte.get('janela', {}).get('prazo_segundos')} segundos")
print(f"Prazo Limite Cravado (T_max): {dados_corte.get('janela', {}).get('prazo_limite_utc')}")
print(f"Hash Intermediário Lavrado no Livro: {dados_corte.get('hash_intermediario', '')[:24]}...")

print("\n=== 8. CÁLCULO E AUDITORIA DE DEMANDA ESTATÍSTICA ===")
from main import calcular_demanda

# Amostras de dispersão e confiança
valores = [0.88, 0.92, 0.85, 0.90]

# Chamada com atribuição e exibição pericial no console:
resultado = calcular_demanda(valores)
print("Resultado da verificação:", resultado)

print("\n=== 9. BANCADA DE ESTRESSE: DISPARO CONCORRENTE COM MICROSSEGUNDOS ===")
import asyncio
from bancada_concorrente import executar_bancada_estresse

asyncio.run(executar_bancada_estresse(total_eventos=15))
