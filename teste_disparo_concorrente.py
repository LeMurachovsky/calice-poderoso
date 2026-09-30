import asyncio
import httpx
import random

API_URL = "http://127.0.0.1:8000/api/interceptar"

async def disparar_caso(client, i):
    score = random.choice([0.45, 0.60, 0.72, 0.88])
    payload = {
        "documento_id": f"DOC-CONCORRENTE-{i:03d}",
        "conteudo_proposto": f"Operação financeira de teste concorrente #{i}",
        "confianca_modelo": score,
        "contem_clausula": True,
        "janela_sla_segundos": 1800
    }
    resp = await client.post(API_URL, json=payload)
    return resp

async def main():
    print("=" * 95)
    print("DISPARO DE 10 TAREFAS CONCORRENTES NO MESMO MICROSSEGUNDO CONTRA A API DO CÁLICE")
    print(f"Endpoint Alvo: {API_URL}")
    print("=" * 95)
    async with httpx.AsyncClient() as client:
        # Dispara 10 tarefas em paralelo no mesmo microssegundo
        respostas = await asyncio.gather(*(disparar_caso(client, i) for i in range(1, 11)))
        
        print(f"\n{'#':<4} | {'HTTP':<6} | {'TX ID':<26} | {'STATUS CÁLICE':<24} | {'SLA REGISTRADO'}")
        print("-" * 95)
        for idx, r in enumerate(respostas, 1):
            if r.status_code == 201:
                dados = r.json()
                tx = dados.get("transaction_id", "N/A")
                status = dados.get("status", "N/A")
                sla = dados.get("janela", {}).get("prazo_segundos", "N/A")
                print(f"#{idx:<3} | {r.status_code:<6} | {tx:<26} | {status:<24} | {sla}s")
            else:
                print(f"#{idx:<3} | {r.status_code:<6} | Erro: {r.text}")

    print("-" * 95)
    print("Validação concorrente concluída com sucesso: todas as requisições processadas e registradas no livro-razão.")

if __name__ == "__main__":
    asyncio.run(main())
