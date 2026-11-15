import hashlib

from auditor.analyzer import analyze, base_word, has_keyboard_walk, has_sequence
from auditor.generator import passphrase
from auditor.hibp import parse_range, pwned_count, split_hash


def test_senha_comum_com_leet_continua_fraca():
    rep = analyze("S3nh@2024!")
    assert rep.score <= 1
    assert any("mais usadas" in p for p in rep.problems)


def test_frase_longa_e_aleatoria_e_forte():
    rep = analyze("girafa-telhado-pipoca-vulcao-remo-42")
    assert rep.score >= 3


def test_detecta_sequencia_e_teclado():
    assert has_sequence("ab1234cd")
    assert has_sequence("xx9876")
    assert has_keyboard_walk("Qwerty!!")
    assert not has_sequence("a1b2c3")


def test_informacao_pessoal_derruba_a_nota():
    sem = analyze("Arthur#Lince#Sorocaba")
    com = analyze("Arthur#Lince#Sorocaba", ["arthur", "sorocaba"])
    assert com.bits < sem.bits


def test_base_word_tira_leet_e_pontas():
    assert base_word("!!P@ssw0rd2024") == "password"


def test_hibp_split_e_parse():
    prefix, suffix = split_hash("password")
    assert prefix == hashlib.sha1(b"password").hexdigest().upper()[:5]
    body = f"0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n{suffix}:9545824\r\n"
    assert parse_range(body, suffix) == 9545824


def test_hibp_so_envia_prefixo():
    sent = []

    def fake_fetch(prefix):
        sent.append(prefix)
        return "AAAA:1"

    assert pwned_count("uma senha qualquer", fetch=fake_fetch) == 0
    assert len(sent[0]) == 5


def test_gerador_tem_palavras_e_numero():
    frase = passphrase(4)
    partes = frase.split("-")
    assert len(partes) == 5
    assert partes[-1].isdigit()
