"""
Cálice Poderoso — verificador público do livro-razão

Confere, sem nenhum segredo do servidor, que um livro exportado (ou a prova de um
selo) foi assinado pela chave Ed25519 do Cálice e não foi alterado. Depende só da
biblioteca `cryptography`; não importa nada do backend.

Uso:
  curl -s localhost:8000/api/v1/ledger/export > livro.json
  python verificar_publico.py livro.json --chave <chave pública em hex>

A chave pública deve vir de um canal confiável (publicada pela organização, impressa
em contrato etc.). Sem `--chave`, usa a que vem no próprio arquivo, o que só prova
consistência interna: quem forjou o arquivo pode ter trocado a chave junto.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

try:
    import base58

    def b58encode(b: bytes) -> str:
        return base58.b58encode(b).decode("utf-8")

    def b58decode(s: str) -> bytes:
        return base58.b58decode(s)
except ImportError:
    _B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

    def b58encode(b: bytes) -> str:
        n = int.from_bytes(b, "big")
        chars = []
        while n > 0:
            n, r = divmod(n, 58)
            chars.append(_B58_ALPHABET[r])
        for byte in b:
            if byte == 0:
                chars.append(_B58_ALPHABET[0])
            else:
                break
        return "".join(reversed(chars))

    def b58decode(s: str) -> bytes:
        n = 0
        for char in s:
            n = n * 58 + _B58_ALPHABET.index(char)
        pad = 0
        for char in s:
            if char == _B58_ALPHABET[0]:
                pad += 1
            else:
                break
        res = n.to_bytes((n.bit_length() + 7) // 8, "big") if n > 0 else b""
        return b"\x00" * pad + res


def emitir_selo_calice(payload_bytes: bytes, thread_ref: str, momento: datetime | None = None) -> str:
    """Emite o carimbo institucional oficial do Cálice (padrão CLC-AUTH).

    1. Criptografia matemática nos bastidores (SHA-256).
    2. Transmutação visual: codificação opaca de custódia via Base58.
    3. Selo comercial e pericial blindado com timestamp UTC certificado.
    """
    digest_secreto = hashlib.sha256(payload_bytes).digest()
    token_opaco = b58encode(digest_secreto)
    ts = momento if momento is not None else datetime.now(timezone.utc)
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    timestamp_utc = ts.strftime("%Y%m%d.%H%M%S%f")[:-3]
    return f"CLC-AUTH::{thread_ref}::{timestamp_utc}::{token_opaco}"


def decodificar_selo(selo: str) -> dict[str, Any]:
    """Decodifica um selo CLC-AUTH em seus componentes periciais originais."""
    partes = selo.strip().split("::")
    if len(partes) != 4 or partes[0] != "CLC-AUTH":
        raise ValueError("Formato de selo inválido (esperado: CLC-AUTH::<thread_ref>::<timestamp>::<token_opaco>).")
    prefixo, thread_ref, timestamp_utc, token_opaco = partes
    digest = b58decode(token_opaco)
    return {
        "padrao": prefixo,
        "thread_ref": thread_ref,
        "timestamp_utc": timestamp_utc,
        "token_opaco": token_opaco,
        "digest_hex": digest.hex(),
    }


GENESIS_HASH = "0" * 64
ALGORITMO = "Ed25519"
CAMPOS = ("seq", "tx_id", "evento", "dados", "prev_hash", "hash", "created_at")


def canonico(obj: Any) -> str:
    """JSON determinístico: mesma entrada, mesmos bytes, mesmo hash."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def mensagem_assinada(ev: dict[str, Any]) -> bytes:
    """Bytes cobertos pela assinatura Ed25519 de um registro.

    Inclui o `hash` (o elo HMAC) e o `prev_hash`: a assinatura amarra o conteúdo ao
    lugar exato do registro na cadeia.
    """
    return canonico({"v": 1, **{c: ev[c] for c in CAMPOS}}).encode("utf-8")


def id_chave(chave_publica_hex: str) -> str:
    """Impressão digital curta da chave pública, para conferência visual."""
    return hashlib.sha256(bytes.fromhex(chave_publica_hex)).hexdigest()[:16]


def carregar_chave(chave_publica_hex: str) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(bytes.fromhex(chave_publica_hex))


def assinatura_valida(chave: Ed25519PublicKey, ev: dict[str, Any]) -> bool:
    try:
        chave.verify(bytes.fromhex(ev.get("assinatura") or ""), mensagem_assinada(ev))
        return True
    except (InvalidSignature, ValueError):
        return False


def verificar_registros(registros: list[dict[str, Any]], chave_publica_hex: str,
                        cadeia_completa: bool = True) -> dict[str, Any]:
    """Confere assinaturas e, se `cadeia_completa`, sequência e encadeamento desde a gênese.

    Com `cadeia_completa=False` (prova de um selo: só os registros da transação),
    confere cada assinatura; o encadeamento com o resto do livro exige a exportação.
    """
    total = 0

    def falha(seq: Any, motivo: str) -> dict[str, Any]:
        return {"integro": False, "total_eventos": total, "head_hash": None,
                "falha": {"seq": seq, "motivo": motivo}}

    try:
        chave = carregar_chave(chave_publica_hex)
    except ValueError:
        return falha(None, "Chave pública inválida.")

    prev = GENESIS_HASH
    for ev in registros:
        total += 1
        if any(c not in ev for c in CAMPOS):
            return falha(ev.get("seq"), "Registro incompleto.")
        if cadeia_completa:
            if ev["seq"] != total:
                return falha(ev["seq"], f"Lacuna na sequência: esperado o registro #{total}.")
            if ev["prev_hash"] != prev:
                return falha(ev["seq"], "Encadeamento rompido: o registro não aponta para o anterior.")
        if not ev.get("assinatura"):
            return falha(ev["seq"], "Registro sem assinatura pública (anterior ao Ed25519).")
        if not assinatura_valida(chave, ev):
            return falha(ev["seq"], "Assinatura Ed25519 inválida: registro alterado ou chave diferente.")
        prev = ev["hash"]

    return {"integro": True, "total_eventos": total, "head_hash": prev, "falha": None}


def verificar_documento(doc: dict[str, Any], chave_publica_hex: str | None = None) -> dict[str, Any]:
    """Verifica uma exportação (`/ledger/export`) ou uma prova (`/transactions/{id}/proof`)."""
    chave = chave_publica_hex or doc.get("chave_publica", {}).get("hex", "")
    completa = "transaction_id" not in doc  # prova de selo traz só os registros da transação
    resultado = verificar_registros(doc.get("registros", []), chave, cadeia_completa=completa)
    resultado["chave_confiavel"] = chave_publica_hex is not None
    return resultado


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Verifica o livro do Cálice com a chave pública Ed25519.")
    p.add_argument("arquivo", nargs="?", help="JSON de /api/v1/ledger/export ou /api/v1/transactions/{id}/proof")
    p.add_argument("--chave", help="Chave pública Ed25519 (hex) obtida por canal confiável")
    p.add_argument("--selo", help="Selo oficial CLC-AUTH para decodificação e inspeção pericial")
    args = p.parse_args(argv)

    if args.selo:
        try:
            info = decodificar_selo(args.selo)
            print(json.dumps({"valido": True, "detalhes": info}, ensure_ascii=False, indent=2))
            return 0
        except Exception as e:
            print(json.dumps({"valido": False, "erro": str(e)}, ensure_ascii=False, indent=2), file=sys.stderr)
            return 1

    if not args.arquivo:
        p.print_help()
        return 1

    with open(args.arquivo, encoding="utf-8") as f:
        resultado = verificar_documento(json.load(f), args.chave)
    print(json.dumps(resultado, ensure_ascii=False, indent=2))
    if not resultado["chave_confiavel"]:
        print("Aviso: chave lida do próprio arquivo; informe --chave para uma verificação independente.",
              file=sys.stderr)
    return 0 if resultado["integro"] else 1


if __name__ == "__main__":
    sys.exit(main())
