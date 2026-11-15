"""Consulta ao Pwned Passwords do Have I Been Pwned usando k-anonymity.

A senha nunca sai da máquina. Eu calculo o SHA-1, mando só os 5 primeiros
caracteres do hash e a API devolve todos os sufixos que começam com esse
prefixo (centenas deles). A comparação final acontece aqui do meu lado.
"""
from __future__ import annotations

import hashlib
import urllib.request

API = "https://api.pwnedpasswords.com/range/{}"


def split_hash(password: str) -> tuple[str, str]:
    digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    return digest[:5], digest[5:]


def parse_range(body: str, suffix: str) -> int:
    for line in body.splitlines():
        candidate, _, count = line.strip().partition(":")
        if candidate.upper() == suffix:
            return int(count)
    return 0


def fetch_range(prefix: str, timeout: float = 10.0) -> str:
    req = urllib.request.Request(
        API.format(prefix),
        headers={"User-Agent": "password-auditor-estudo", "Add-Padding": "true"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8")


def pwned_count(password: str, fetch=fetch_range) -> int:
    prefix, suffix = split_hash(password)
    return parse_range(fetch(prefix), suffix)
