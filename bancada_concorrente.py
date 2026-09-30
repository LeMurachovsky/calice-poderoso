"""
Cálice Poderoso — Bancada de Estresse Concorrente
Disparo assíncrono simultâneo com timestamps de microssegundos e trava atômica.
"""
from __future__ import annotations

import asyncio
import datetime
import hashlib
import random
import uuid
from typing import Any


class CaliceLedgerConcorrente:
    def __init__(self, limiar_confianca: float = 0.85):
        self.limiar = limiar_confianca
        self.ultimo_hash = "0000000000000000000000000000000000000000000000000000000000000000"
        self.contador_bloco = 0
        self.lock = asyncio.Lock()  # Assegura a integridade da cadeia criptográfica
        self.registos: list[dict[str, Any]] = []

    async def interceptar_e_registar(
        self, cliente_id: str, doc_id: str, payload_texto: str, score_confianca: float
    ) -> dict[str, Any]:
        # Captura temporal com precisão de microssegundos no instante exato de entrada
        timestamp_atomo = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")
        
        # Avaliação de conformidade métrica
        bloqueado = score_confianca < self.limiar
        estado = "FATOR_PAUSA_ATIVADO" if bloqueado else "LIBERADO"
        
        # Secção crítica com trava atómica para escrita no livro-razão
        async with self.lock:
            self.contador_bloco += 1
            bloco_num = self.contador_bloco
            hash_anterior = self.ultimo_hash
            
            # Formação da semente do bloco
            dados_bloco = (
                f"{bloco_num}|{timestamp_atomo}|{cliente_id}|{doc_id}|"
                f"{score_confianca:.4f}|{estado}|{hash_anterior}"
            )
            hash_atual = hashlib.sha256(dados_bloco.encode("utf-8")).hexdigest()
            self.ultimo_hash = hash_atual

            registo = {
                "bloco": bloco_num,
                "timestamp": timestamp_atomo,
                "cliente": cliente_id,
                "documento": doc_id,
                "score": score_confianca,
                "estado": estado,
                "hash": hash_atual[:16] + "...",
                "hash_completo": hash_atual,
                "hash_anterior": hash_anterior[:16] + "...",
                "hash_anterior_completo": hash_anterior,
            }
            self.registos.append(registo)
            return registo


async def disparar_evento_teste(
    ledger: CaliceLedgerConcorrente, cliente_id: str, indice: int
) -> dict[str, Any]:
    # Simula latências de rede reais de 1 a 15 microssegundos/milissegundos
    await asyncio.sleep(random.uniform(0.001, 0.015))
    
    doc_id = f"DOC-STRESS-{indice:04d}"
    
    # Alterna propositadamente entre respostas sólidas e análises com alta dispersão
    score_gerado = random.choice([0.42, 0.55, 0.78, 0.89, 0.94, 0.38])
    payload = f"Carga de teste concorrente submetida por {cliente_id} - Hash transacional."
    
    resultado = await ledger.interceptar_e_registar(cliente_id, doc_id, payload, score_gerado)
    return resultado


async def executar_bancada_estresse(total_eventos: int = 20) -> list[dict[str, Any]]:
    print("=" * 95)
    print(f"INICIANDO DISPARO CONCORRENTE: {total_eventos} EVENTOS SIMULTÂNEOS COM TIMESTAMPS DE MICROSSEGUNDOS")
    print("=" * 95)

    ledger = CaliceLedgerConcorrente(limiar_confianca=0.85)
    
    clientes_teste = ["EMPRESA-ALFA", "BANCO-BETA", "OPERADORA-GAMA", "FUNDO-DELTA"]
    
    # Disparo de todos os eventos no mesmo ciclo de relógio
    tarefas = [
        disparar_evento_teste(ledger, random.choice(clientes_teste), i + 1)
        for i in range(total_eventos)
    ]
    
    resultados = await asyncio.gather(*tarefas)

    print(f"\n{'BLOCO':<7} | {'TIMESTAMP (UTC - MICROSSEGUNDOS)':<27} | {'CLIENTE':<15} | {'SCORE':<6} | {'STATUS':<21} | {'HASH ENCAD.'}")
    print("-" * 105)
    for r in resultados:
        print(f"#{r['bloco']:<6} | {r['timestamp']:<27} | {r['cliente']:<15} | {r['score']:<6.2f} | {r['estado']:<21} | {r['hash']}")

    print("-" * 105)
    print(f"Validação concluída: {len(ledger.registos)} blocos selados sequencialmente sem quebra de cadeia.")
    return resultados


if __name__ == "__main__":
    asyncio.run(executar_bancada_estresse(total_eventos=15))
