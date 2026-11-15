"""Análise de força de senha.

Entropia "de livro" (tamanho vezes log2 do alfabeto) é otimista demais.
A senha "Senha@2024" tem 10 caracteres de 4 grupos e daria uns 65 bits,
mas qualquer wordlist decente quebra ela em segundos. Por isso eu calculo
a entropia bruta e depois desconto os padrões que um atacante testa primeiro.
"""
from __future__ import annotations

import math
import re
import string
from dataclasses import dataclass, field
from importlib import resources

KEYBOARD_ROWS = ["1234567890", "qwertyuiop", "asdfghjkl", "zxcvbnm"]
LEET = str.maketrans({"@": "a", "4": "a", "3": "e", "1": "i", "!": "i", "0": "o", "$": "s", "5": "s", "7": "t"})

# Taxas de chute por segundo usadas na estimativa de tempo
SCENARIOS = {
    "online com limite de tentativas": 10 / 3600,
    "online sem limite": 100,
    "offline com bcrypt": 10_000,
    "offline com MD5 em GPU": 10_000_000_000,
}


def _load_common() -> set[str]:
    text = resources.files("auditor").joinpath("data/comuns.txt").read_text(encoding="utf-8")
    return {line.strip().lower() for line in text.splitlines() if line.strip() and not line.startswith("#")}


COMMON = _load_common()


@dataclass
class Report:
    password_length: int
    charset_size: int
    raw_bits: float
    bits: float
    score: int
    label: str
    problems: list[str] = field(default_factory=list)
    tips: list[str] = field(default_factory=list)
    crack_times: dict[str, str] = field(default_factory=dict)
    pwned_count: int | None = None


def charset_size(pw: str) -> int:
    size = 0
    if any(c in string.ascii_lowercase for c in pw):
        size += 26
    if any(c in string.ascii_uppercase for c in pw):
        size += 26
    if any(c in string.digits for c in pw):
        size += 10
    if any(c in string.punctuation or c == " " for c in pw):
        size += 33
    if any(ord(c) > 127 for c in pw):
        size += 64
    return size


def has_sequence(pw: str, size: int = 4) -> bool:
    """Detecta abcd, 1234, dcba e afins."""
    low = pw.lower()
    for i in range(len(low) - size + 1):
        chunk = low[i:i + size]
        diffs = {ord(b) - ord(a) for a, b in zip(chunk, chunk[1:])}
        if diffs in ({1}, {-1}):
            return True
    return False


def has_keyboard_walk(pw: str, size: int = 4) -> bool:
    low = pw.lower()
    for row in KEYBOARD_ROWS:
        for i in range(len(row) - size + 1):
            piece = row[i:i + size]
            if piece in low or piece[::-1] in low:
                return True
    return False


def has_repetition(pw: str) -> bool:
    return re.search(r"(.)\1{2,}", pw) is not None or re.search(r"(.{2,})\1", pw) is not None


def has_date(pw: str) -> bool:
    return re.search(r"(19[5-9]\d|20[0-4]\d)", pw) is not None or re.search(
        r"(0[1-9]|[12]\d|3[01])(0[1-9]|1[0-2])\d{2,4}", pw
    ) is not None


def base_word(pw: str) -> str:
    """Tira leetspeak, números e símbolos das pontas. 'S3nh@2024!' vira 'senha'."""
    # primeiro tiro o "enfeite" das pontas (anos, números e símbolos soltos),
    # só depois troco o leet, senão o @ de "s3nh@" sumiria junto
    core = re.sub(r"(\d+|[!#%&*?._\-])+$", "", pw)
    core = re.sub(r"^(\d+|[!#%&*?._\-])+", "", core)
    return core.lower().translate(LEET)


def human_time(seconds: float) -> str:
    if seconds < 1:
        return "na hora"
    units = [("séculos", 3600 * 24 * 365 * 100), ("anos", 3600 * 24 * 365), ("dias", 3600 * 24),
             ("horas", 3600), ("minutos", 60), ("segundos", 1)]
    for name, size in units:
        if seconds >= size:
            value = seconds / size
            if name == "séculos" and value > 1000:
                return "mais de mil séculos"
            return f"{value:.0f} {name}"
    return "na hora"


def analyze(pw: str, user_info: list[str] | None = None) -> Report:
    size = charset_size(pw)
    raw = len(pw) * math.log2(size) if size else 0.0
    bits = raw
    problems: list[str] = []
    tips: list[str] = []

    if len(pw) < 12:
        problems.append(f"tem só {len(pw)} caracteres, o NIST recomenda aceitar senhas longas e o ideal é 12 ou mais")
        tips.append("aumente o tamanho, uma frase com 4 palavras aleatórias é fácil de lembrar e difícil de quebrar")
    if pw.lower() in COMMON or base_word(pw) in COMMON:
        problems.append("está (ou é variação de algo que está) nas listas de senhas mais usadas")
        bits = min(bits, 10)
    if has_sequence(pw):
        problems.append("tem sequência tipo 1234 ou abcd")
        bits -= 10
    if has_keyboard_walk(pw):
        problems.append("tem caminho de teclado tipo qwer ou asdf")
        bits -= 10
    if has_repetition(pw):
        problems.append("repete caracteres ou blocos")
        bits -= 8
    if has_date(pw):
        problems.append("parece ter um ano ou data, que é o primeiro chute de quem te conhece")
        bits -= 8
    for info in user_info or []:
        if info and len(info) >= 3 and info.lower() in pw.lower():
            problems.append(f"contém uma informação pessoal ({info})")
            bits -= 15
    if size <= 26 and len(pw) < 16:
        tips.append("misture tipos de caractere ou use uma frase bem mais longa")

    if len(pw) < 12:
        bits = min(bits, 59.0)  # senha curta nunca passa de "razoável"
    bits = max(bits, 0.0)
    if bits < 28:
        score, label = 0, "muito fraca"
    elif bits < 40:
        score, label = 1, "fraca"
    elif bits < 60:
        score, label = 2, "razoável"
    elif bits < 80:
        score, label = 3, "forte"
    else:
        score, label = 4, "muito forte"

    guesses = 2 ** bits / 2  # na média o atacante acha na metade do espaço
    crack = {name: human_time(guesses / rate) for name, rate in SCENARIOS.items()}
    if score >= 3 and not tips:
        tips.append("boa senha, agora guarde ela num gerenciador e ative 2FA")

    return Report(len(pw), size, round(raw, 1), round(bits, 1), score, label, problems, tips, crack)
