# Cálice Poderoso v2

business with Leandro Murachovsky

Camada de governança *human-in-the-loop* para decisões de IA. Toda proposta da IA é interceptada, avaliada por regras e só segue com **juízo humano registrado**: operador identificado, justificativa escrita e ciência declarada de cada violação. Cada evento vai para um livro de registros encadeado e assinado (HMAC-SHA256), verificável a qualquer momento.

## Rodando

Requer Python 3.10+.

```bash
pip install -r requirements.txt
export CALICE_SIGNING_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
uvicorn main:app --reload
```

Abra http://127.0.0.1:8000 (interface) ou http://127.0.0.1:8000/docs (Swagger).

| Variável | Padrão | Função |
|---|---|---|
| `CALICE_SIGNING_KEY` | chave de desenvolvimento (com aviso no log e na interface) | Chave secreta das assinaturas do livro |
| `CALICE_DB_PATH` | `./calice.db` | Caminho do SQLite |
| `CALICE_CONFIDENCE_THRESHOLD` | `0.85` | Confiança mínima exigida da IA |

Guarde a chave: trocá-la invalida a verificação de todo o livro já gravado.

## Endpoints

| Método | Rota | O que faz |
|---|---|---|
| POST | `/api/v1/intercept` | Intercepta uma proposta e roda as regras (201) |
| POST | `/api/v1/seal` | Chancela: exige ciência de todas as violações (422 se faltar, 409 se já decidida) |
| POST | `/api/v1/reject` | Rejeita a proposta com justificativa |
| GET | `/api/v1/transactions?status=&limit=` | Fila com resumo por status |
| GET | `/api/v1/transactions/{tx_id}` | Detalhe com conteúdo e eventos do livro |
| GET | `/api/v1/ledger/verify` | Verifica sequência, encadeamento, assinaturas e consistência |
| GET | `/api/v1/health` | Saúde do serviço |

Exemplo de chancela:

```bash
curl -X POST localhost:8000/api/v1/seal -H 'Content-Type: application/json' -d '{
  "transaction_id": "TX-...",
  "operator_name": "Marina Couto",
  "notes": "Pagamento previsto em contrato; risco aceito pela diretoria.",
  "acknowledged_violations": ["LACUNA_JURIDICA", "CONFIANCA_BAIXA"]
}'
```

## Adicionando uma regra

Uma regra é uma função decorada com `@regra` que devolve `Violacao` ou `None`. Não precisa mexer em mais nada do backend:

```python
import re

@regra
def valor_acima_da_alcada(req: InterceptRequest, cfg: Settings) -> Violacao | None:
    valores = re.findall(r"R\$\s*([\d.]+),\d{2}", req.content)
    if any(float(v.replace(".", "")) > 100_000 for v in valores):
        return Violacao("ALCADA_EXCEDIDA", "ALTA", "Valor acima da alçada de R$ 100.000,00.")
    return None
```

Na interface, acrescente o nome legível em `NOMES` (`static/index.html`); sem isso, o código aparece como está.

## Testes

```bash
pytest -q
```

Cobrem validação, ciência obrigatória, duplicidade (409), concorrência (8 chancelas simultâneas → exatamente uma passa), encadeamento linear e detecção de adulteração no livro, na projeção e com chave errada.

Para ver a detecção na prática, altere um registro direto no banco (os triggers bloqueiam `UPDATE`, então remova-os antes, simulando um atacante com acesso ao arquivo) e chame `/api/v1/ledger/verify`: a resposta aponta o `seq` adulterado, e a interface exibe o alerta.

## Limites conhecidos

- HMAC é simétrico: quem verifica também consegue assinar. Para verificação por terceiros, use Ed25519 ou carimbo do tempo (RFC 3161 / ICP-Brasil).
- A identidade do operador é declarada, não autenticada. Próximo passo: autenticação.
- O rótulo `CUSTODIA_PROBATORIA_CPC` descreve a intenção; validade jurídica depende de análise jurídica própria.
