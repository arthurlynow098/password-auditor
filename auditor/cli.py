from __future__ import annotations

import argparse
import getpass
import sys

from .analyzer import analyze
from .generator import passphrase, passphrase_bits
from .hibp import pwned_count

BAR = ["█░░░░", "██░░░", "███░░", "████░", "█████"]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="auditor", description="Mede a força de uma senha e checa se ela já vazou.")
    p.add_argument("--hibp", action="store_true", help="consulta o Have I Been Pwned (só o prefixo do hash sai da máquina)")
    p.add_argument("--info", nargs="*", default=[], help="nome, apelido, ano de nascimento, para checar se estão na senha")
    p.add_argument("--gerar", type=int, metavar="N", help="gera uma frase-senha com N palavras")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)

    if args.gerar:
        frase = passphrase(args.gerar)
        print(f"\n  {frase}\n  cerca de {passphrase_bits(args.gerar):.0f} bits de entropia\n")
        return 0

    # getpass não mostra a senha na tela e ela não fica no histórico do terminal
    pw = getpass.getpass("  senha para analisar (não aparece na tela) ")
    if not pw:
        print("nenhuma senha digitada", file=sys.stderr)
        return 1

    rep = analyze(pw, args.info)
    if args.hibp:
        try:
            rep.pwned_count = pwned_count(pw)
        except OSError as exc:
            print(f"  não consegui falar com a API do HIBP ({exc})", file=sys.stderr)

    print(f"\n  força   {BAR[rep.score]}  {rep.label}")
    print(f"  bits    {rep.bits} efetivos de {rep.raw_bits} brutos ({rep.password_length} caracteres)")
    if rep.pwned_count:
        print(f"\n  ALERTA  essa senha apareceu {rep.pwned_count:,} vezes em vazamentos. Troque agora.".replace(",", "."))
    elif rep.pwned_count == 0:
        print("\n  boa     não apareceu em nenhum vazamento conhecido do HIBP")
    if rep.problems:
        print("\n  problemas encontrados")
        for prob in rep.problems:
            print(f"   x {prob}")
    print("\n  tempo estimado para quebrar")
    for scenario, t in rep.crack_times.items():
        print(f"   {scenario:<34}{t}")
    if rep.tips:
        print("\n  dicas")
        for tip in rep.tips:
            print(f"   > {tip}")
    print()
    return 0
