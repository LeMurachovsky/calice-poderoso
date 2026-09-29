# Cálice Poderoso v2

business with Leandro Murachovsky

Camada de governança *human-in-the-loop* para decisões de IA. Toda proposta da IA é interceptada, avaliada por regras e só segue com **juízo humano registrado**: operador identificado, justificativa escrita e ciência declarada de cada violação. Cada evento vai para um livro de registros encadeado e assinado duas vezes: HMAC-SHA256 (elo da cadeia) e Ed25519 (assinatura pública), que qualquer terceiro confere só com a chave pública.

## Rodando

Requer Python 3.10+.

```bash
pip install -r requirements.txt
export CALICE_SIGNING_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
python main.py operador criar marina "Marina Couto"   # pede a senha no terminal
uvicorn main:app --reload
```

Abra http://127.0.0.1:8000 (interface) ou http://127.0.0.1:8000/docs (Swagger).

| Variável | Padrão | Função |
|---|---|---|
| `CALICE_SIGNING_KEY` | chave de desenvolvimento (com aviso no log e na interface) | Chave secreta das assinaturas do livro |
| `CALICE_ED25519_SEED` | derivada de `CALICE_SIGNING_KEY` | Semente Ed25519 (64 caracteres hex) da assinatura pública |
| `CALICE_DB_PATH` | `./calice.db` | Caminho do SQLite |
| `CALICE_CONFIDENCE_THRESHOLD` | `0.85` | Confiança mínima exigida da IA |
| `CALICE_SESSION_HOURS` | `8` | Validade do token de sessão do operador, em horas |

Guarde as chaves: trocá-las invalida a verificação de todo o livro já gravado. Para gerar uma semente Ed25519 própria: `python -c 'import secrets; print(secrets.token_hex(32))'`.

## Operadores

Só operadores autenticados chancelam ou rejeitam. O nome gravado no selo e no livro vem da conta, não do que o cliente envia; o livro também registra o `operador_login`.

```bash
python main.py operador criar <login> "<Nome completo>"   # senha de 12+ caracteres, pedida no terminal
python main.py operador senha <login>                      # troca a senha e encerra as sessões abertas
python main.py operador desativar <login>                  # bloqueia e encerra as sessões abertas
python main.py operador reativar <login>
python main.py operador listar
```

Senhas ficam com scrypt (sal individual); tokens de sessão são aleatórios e o banco guarda só o SHA-256 deles. Na interface, o operador entra no painel "Juízo humano"; a sessão vive só na aba aberta.

## Endpoints

| Método | Rota | O que faz |
|---|---|---|
| POST | `/api/v1/intercept` | Intercepta uma proposta e roda as regras (201) |
| POST | `/api/v1/auth/login` | Troca login e senha por um token de sessão (401 se não conferir) |
| POST | `/api/v1/auth/logout` | Encerra a sessão do token enviado |
| GET | `/api/v1/auth/me` | Operador da sessão atual |
| POST | `/api/v1/seal` | Chancela (exige token): ciência de todas as violações (422 se faltar, 409 se já decidida) |
| POST | `/api/v1/reject` | Rejeita a proposta com justificativa (exige token) |
| GET | `/api/v1/transactions?status=&limit=` | Fila com resumo por status |
| GET | `/api/v1/transactions/{tx_id}` | Detalhe com conteúdo e eventos do livro |
| GET | `/api/v1/transactions/{tx_id}/proof` | Registros assinados de uma transação, para conferência por terceiros |
| GET | `/api/v1/ledger/verify` | Verifica sequência, encadeamento, assinaturas e consistência |
| GET | `/api/v1/ledger/public-key` | Chave pública Ed25519 (hex) e sua impressão digital |
| GET | `/api/v1/ledger/export` | Livro completo com as assinaturas Ed25519 |
| POST | `/api/v1/topics/{topic_id}/outcomes` | Publica no tópico o desfecho de uma transação chancelada (exige token; 409 se não chancelada ou repetida) |
| GET | `/api/v1/topics/{topic_id}/context` | Linha do tempo chancelada do tópico, em lista e em texto pronto para o prompt |
| GET | `/api/v1/health` | Saúde do serviço |

Exemplo de chancela:

```bash
TOKEN=$(curl -s -X POST localhost:8000/api/v1/auth/login -H 'Content-Type: application/json' \
  -d '{"login": "marina", "password": "..."}' | python -c 'import json,sys; print(json.load(sys.stdin)["token"])')

curl -X POST localhost:8000/api/v1/seal -H 'Content-Type: application/json' -H "Authorization: Bearer $TOKEN" -d '{
  "transaction_id": "TX-...",
  "notes": "Pagamento previsto em contrato; risco aceito pela diretoria.",
  "acknowledged_violations": ["LACUNA_JURIDICA", "CONFIANCA_BAIXA"]
}'
```

## Verificação por terceiros

Cada registro do livro leva uma assinatura Ed25519 sobre o seu conteúdo, o `hash` e o `prev_hash`. Quem recebe o livro não precisa de nenhum segredo do servidor para conferi-lo: basta a chave pública, obtida por um canal confiável (publicada pela organização, anexada ao contrato).

```bash
curl -s localhost:8000/api/v1/ledger/public-key          # publique o campo "hex"
curl -s localhost:8000/api/v1/ledger/export > livro.json
python verificar_publico.py livro.json --chave <hex>     # sai com 0 se íntegro
```

`verificar_publico.py` só depende de `cryptography` e não importa o backend; pode ser entregue ao auditor sozinho. Ele confere sequência, encadeamento desde a gênese e cada assinatura. Para um selo isolado, `GET /api/v1/transactions/{tx_id}/proof` traz os registros da transação (o conteúdo aparece só como `content_sha256`, que o auditor confere com o documento em mãos); o mesmo script verifica as assinaturas, e o encadeamento com o resto do livro pede a exportação completa.

Registros gravados antes desta versão não têm assinatura Ed25519: continuam protegidos pelo HMAC no `/ledger/verify`, mas a verificação pública os aponta como não assinados.

## Sincronização entre janelas

Quando várias janelas (sessões de IA) tratam do mesmo assunto, cada desfecho chancelado pode ser publicado num tópico, e a janela seguinte recebe o que já foi fixado antes de começar:

```bash
curl -X POST localhost:8000/api/v1/topics/contrato-42/outcomes -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $TOKEN" -d '{
    "transaction_id": "TX-...", "janela": "janela-A", "dados": {"prazo_dias": 30}
  }'
curl -s localhost:8000/api/v1/topics/contrato-42/context   # campo "contexto": texto para o prompt da janela B
```

Só entra no tópico uma transação `CHANCELADO_E_CONCLUIDO`; a certidão é o `proof_hash` da chancela, lido do banco. Cada publicação vira um evento `SINCRONIZACAO` no livro (assinado e coberto pelo `/ledger/verify`), e a tabela `desfechos_topico` é só o índice por tópico.

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

Cobrem validação, autenticação do operador (sem token, token inválido ou expirado, operador desativado, nome forjado no corpo), ciência obrigatória, duplicidade (409), concorrência (8 chancelas simultâneas → exatamente uma passa), encadeamento linear, detecção de adulteração no livro, na projeção e com chave errada, e a verificação pública Ed25519 (exportação, prova de selo, registros alterados, removidos ou reordenados, chave trocada e banco legado), e a sincronização entre janelas (só chancelados, sem repetição, isolamento por tópico, identificadores que não forjam linhas no contexto e adulteração do índice).

Para ver a detecção na prática, altere um registro direto no banco (os triggers bloqueiam `UPDATE`, então remova-os antes, simulando um atacante com acesso ao arquivo) e chame `/api/v1/ledger/verify`: a resposta aponta o `seq` adulterado, e a interface exibe o alerta.

## Limites conhecidos

- A assinatura Ed25519 prova quem assinou, não quando: o operador do servidor, com a chave privada, ainda poderia reescrever o livro inteiro. Para ancorar no tempo, publique o `head_hash` periodicamente ou use carimbo do tempo (RFC 3161 / ICP-Brasil).
- Não há rotação de chave: a mesma chave pública precisa conferir todo o livro.
- O operador é autenticado por senha, sem segundo fator nem limite de tentativas de login; atrás de um proxy, limite a taxa em `/api/v1/auth/login`. Integração com SSO (OIDC) seria o próximo passo.
- `/api/v1/intercept` e as rotas de leitura continuam abertas: autenticar a IA que submete propostas (chave de API) é um passo separado.
- O rótulo `CUSTODIA_PROBATORIA_CPC` descreve a intenção; validade jurídica depende de análise jurídica própria.
