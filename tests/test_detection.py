import base64
import bz2
import codecs
import gzip
import zlib

import pytest

from cryptohunter.engine import analyze

EN = "the quick brown fox jumps over the lazy dog and this is a secret message"
ES = "hola mundo este es un mensaje secreto para probar la herramienta de cifrado"
MSG = "este es un mensaje secreto muy importante"
LONG_EN = (
    "we will meet at the old house near the river tonight and you must bring the "
    "secret message with you because the people who are looking for it know that "
    "we have it and they will not stop until they find it"
)
LONG_ES = (
    "nos vamos a reunir esta noche en la casa vieja cerca del rio y tienes que traer "
    "el mensaje secreto porque las personas que lo buscan saben que lo tenemos y no "
    "van a parar hasta encontrarlo"
)


def caesar(text, k):
    return "".join(chr((ord(c) - 97 + k) % 26 + 97) if c.islower() else c for c in text)


def vigenere(text, key):
    out, i = [], 0
    for c in text:
        if c.islower():
            out.append(chr((ord(c) - 97 + ord(key[i % len(key)]) - 97) % 26 + 97))
            i += 1
        else:
            out.append(c)
    return "".join(out)


def rail(text, rails):
    rows = [[] for _ in range(rails)]
    pattern = list(range(rails)) + list(range(rails - 2, 0, -1))
    for i, c in enumerate(text):
        rows[pattern[i % len(pattern)]].append(c)
    return "".join("".join(r) for r in rows)


def b58(data):
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    n = int.from_bytes(data, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = alphabet[r] + out
    return out


MORSE = {"h": "....", "o": "---", "l": ".-..", "a": ".-", "m": "--", "u": "..-", "n": "-.", "d": "-.."}

CASES = {
    "base64": (base64.b64encode(MSG.encode()).decode(), MSG),
    "base32": (base64.b32encode(MSG.encode()).decode(), MSG),
    "base85": (base64.b85encode(MSG.encode()).decode(), MSG),
    "ascii85": (base64.a85encode(MSG.encode()).decode(), MSG),
    "base58": (b58(MSG.encode()), MSG),
    "hex": (MSG.encode().hex(), MSG),
    "hex_spaced": (" ".join(f"{b:02x}" for b in MSG.encode()), MSG),
    "binary": (" ".join(f"{b:08b}" for b in ES.encode()), ES),
    "octal": (" ".join(f"{b:o}" for b in ES.encode()), ES),
    "decimal": (" ".join(str(b) for b in ES.encode()), ES),
    "url": ("hola%20mundo%20este%20es%20un%20mensaje%20secreto", "hola mundo este es un mensaje secreto"),
    "html": ("&#104;&#111;&#108;&#97; mundo", "hola mundo"),
    "rot13": (codecs.encode(EN, "rot13"), EN),
    "caesar7": (caesar(EN, 7), EN),
    "caesar_es": (caesar(ES, 19), ES),
    "atbash": (EN.translate(str.maketrans("abcdefghijklmnopqrstuvwxyz", "zyxwvutsrqponmlkjihgfedcba")), EN),
    "reverse": (EN[::-1], EN),
    "vigenere": (vigenere(LONG_EN, "lemon"), LONG_EN),
    "vigenere_es": (vigenere(LONG_ES, "clave"), LONG_ES),
    "rail_fence": (rail(EN, 3), EN),
    "morse": (" ".join(MORSE[c] for c in "hola") + " / " + " ".join(MORSE[c] for c in "mundo"), "HOLA MUNDO"),
    "xor": (bytes(b ^ 0x5A for b in EN.encode()).hex(), EN),
    "zlib_b64": (base64.b64encode(zlib.compress(MSG.encode())).decode(), MSG),
    "gzip_b64": (base64.b64encode(gzip.compress(MSG.encode())).decode(), MSG),
    "bz2_b64": (base64.b64encode(bz2.compress(MSG.encode())).decode(), MSG),
    "b64_hex": (base64.b64encode(MSG.encode().hex().encode()).decode(), MSG),
    "b64_rot13": (base64.b64encode(codecs.encode(EN, "rot13").encode()).decode(), EN),
    "b64_hex_rot13": (base64.b64encode(codecs.encode(EN, "rot13").encode().hex().encode()).decode(), EN),
    "brainfuck": ("".join("+" * ord(c) + ".[-]" for c in "hola mundo"), "hola mundo"),
}


@pytest.mark.parametrize("name", CASES)
def test_detects(name):
    encoded, expected = CASES[name]
    report = analyze(encoded)
    assert report.solved, f"{name}: no resuelto"
    assert report.best.text.lower() == expected.lower(), f"{name}: {report.best.chain} -> {report.best.text!r}"


@pytest.mark.parametrize("text", [EN, ES, "Hola, ¿cómo estás? Todo bien por aquí."])
def test_plaintext_is_left_alone(text):
    assert not analyze(text).solved


def test_hash_no_se_descifra_en_cifrado():
    # un hash no debe "resolverse" como si fuera un cifrado
    assert not analyze("5d41402abc4b2a76b9719d911017c592").solved
