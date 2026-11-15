"""Gerador de frases-senha no estilo diceware, usando o módulo secrets.

random NÃO serve para senha porque é previsível. secrets usa o gerador
criptográfico do sistema operacional.
"""
from __future__ import annotations

import math
import secrets
from importlib import resources


def load_words() -> list[str]:
    text = resources.files("auditor").joinpath("data/palavras.txt").read_text(encoding="utf-8")
    return sorted({w.strip().lower() for w in text.split() if w.strip().isalpha()})


def passphrase(words: int = 5, sep: str = "-", add_number: bool = True) -> str:
    pool = load_words()
    chosen = [secrets.choice(pool) for _ in range(words)]
    if add_number:
        chosen.append(str(secrets.randbelow(100)))
    return sep.join(chosen)


def passphrase_bits(words: int = 5, add_number: bool = True) -> float:
    pool = len(load_words())
    return words * math.log2(pool) + (math.log2(100) if add_number else 0)
