"""Cifrados clásicos con ataque automático (fuerza bruta + análisis de frecuencias)."""

from __future__ import annotations

import re
import string

from .. import scoring
from ..registry import as_text, decoder

LOWER = string.ascii_lowercase
UPPER = string.ascii_uppercase

MORSE = {
    ".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E", "..-.": "F",
    "--.": "G", "....": "H", "..": "I", ".---": "J", "-.-": "K", ".-..": "L",
    "--": "M", "-.": "N", "---": "O", ".--.": "P", "--.-": "Q", ".-.": "R",
    "...": "S", "-": "T", "..-": "U", "...-": "V", ".--": "W", "-..-": "X",
    "-.--": "Y", "--..": "Z", "-----": "0", ".----": "1", "..---": "2",
    "...--": "3", "....-": "4", ".....": "5", "-....": "6", "--...": "7",
    "---..": "8", "----.": "9", ".-.-.-": ".", "--..--": ",", "..--..": "?",
    "-.-.--": "!", "-....-": "-", "-..-.": "/", ".--.-.": "@", "-.--.": "(",
    "-.--.-": ")", "---...": ":", "..--.-": "_", "-...-": "=", ".-.-.": "+",
    "--.--": "Ñ",
}
MORSE_RE = re.compile(r"^[.\-_·•\s/|]+$")


def _alpha(text: str) -> str:
    return "".join(c for c in text if c.isascii() and c.isalpha())


def _is_alpha_text(text: str, min_letters: int = 6) -> bool:
    letters = _alpha(text)
    return len(letters) >= min_letters and len(letters) / max(1, len(text.replace(" ", ""))) > 0.6


def shift_text(text: str, shift: int) -> str:
    out = []
    for c in text:
        if "a" <= c <= "z":
            out.append(LOWER[(ord(c) - 97 + shift) % 26])
        elif "A" <= c <= "Z":
            out.append(UPPER[(ord(c) - 65 + shift) % 26])
        else:
            out.append(c)
    return "".join(out)


def _best(candidates: list[tuple[str, str]], keep: int = 1) -> list[tuple[str, bytes]]:
    ranked = sorted(candidates, key=lambda kv: scoring.score(kv[1]), reverse=True)
    return [(label, txt.encode()) for label, txt in ranked[:keep]]


@decoder("ROT13", "cipher")
def rot13(data: bytes):
    text = as_text(data)
    if not text or not _is_alpha_text(text, 3):
        return []
    return [("ROT13", shift_text(text, 13).encode())]


@decoder("César (fuerza bruta)", "cipher")
def caesar(data: bytes):
    text = as_text(data)
    if not text or not _is_alpha_text(text, 4):
        return []
    cands = [
        (f"César (clave {k})", shift_text(text, -k))
        for k in range(1, 26)
        if k != 13
    ]
    return _best(cands, 2)


@decoder("ROT47", "cipher")
def rot47(data: bytes):
    text = as_text(data)
    if not text or not any(33 <= ord(c) <= 126 for c in text):
        return []
    out = "".join(chr(33 + (ord(c) - 33 + 47) % 94) if 33 <= ord(c) <= 126 else c for c in text)
    return [("ROT47", out.encode())]


@decoder("ROT5 / ROT18", "cipher")
def rot18(data: bytes):
    text = as_text(data)
    if not text or not re.search(r"\d", text):
        return []
    digits = "".join(str((int(c) + 5) % 10) if c.isdigit() else c for c in text)
    out = [("ROT5", digits.encode())]
    if re.search(r"[A-Za-z]", text):
        out.append(("ROT18", shift_text(digits, 13).encode()))
    return out


@decoder("Atbash", "cipher")
def atbash(data: bytes):
    text = as_text(data)
    if not text or not _is_alpha_text(text, 3):
        return []
    table = str.maketrans(LOWER + UPPER, LOWER[::-1] + UPPER[::-1])
    return [("Atbash", text.translate(table).encode())]


@decoder("Afín (fuerza bruta)", "cipher")
def affine(data: bytes):
    text = as_text(data)
    if not text or not _is_alpha_text(text, 8):
        return []
    inverses = {a: pow(a, -1, 26) for a in (1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25)}
    cands = []
    for a, a_inv in inverses.items():
        if a == 1:
            continue  # equivale a César
        for b in range(26):
            out = []
            for c in text:
                if "a" <= c <= "z":
                    out.append(LOWER[(a_inv * (ord(c) - 97 - b)) % 26])
                elif "A" <= c <= "Z":
                    out.append(UPPER[(a_inv * (ord(c) - 65 - b)) % 26])
                else:
                    out.append(c)
            cands.append((f"Afín (a={a}, b={b})", "".join(out)))
    return _best(cands, 1)


def index_of_coincidence(letters: str) -> float:
    n = len(letters)
    if n < 2:
        return 0.0
    counts = [letters.count(c) for c in LOWER]
    return sum(c * (c - 1) for c in counts) / (n * (n - 1))


def _vigenere_decrypt(text: str, key: str) -> str:
    out, i = [], 0
    shifts = [ord(k) - 97 for k in key]
    for c in text:
        if c.isascii() and c.isalpha():
            out.append(shift_text(c, -shifts[i % len(shifts)]))
            i += 1
        else:
            out.append(c)
    return "".join(out)


def _key_for_length(letters: str, length: int, lang: str) -> str:
    key = ""
    for col in range(length):
        column = letters[col::length]
        best = min(range(26), key=lambda s: scoring.chi_squared(shift_text(column, -s), lang))
        key += LOWER[best]
    return key


@decoder("Vigenère (análisis Kasiski/IC)", "cipher")
def vigenere(data: bytes):
    text = as_text(data)
    if not text or not _is_alpha_text(text, 30):
        return []
    letters = _alpha(text).lower()
    if index_of_coincidence(letters) > 0.062:
        return []  # parece monoalfabético, no Vigenère
    lengths = []
    for length in range(2, min(20, len(letters) // 3) + 1):
        ic = sum(index_of_coincidence(letters[i::length]) for i in range(length)) / length
        lengths.append((ic, length))
    # las longitudes pequeñas con IC alto suelen ser la clave real (las grandes
    # son múltiplos de ella o sobreajustan), así que se prueban ambas listas
    small = [length for ic, length in lengths if ic > 0.058][:3]
    lengths.sort(reverse=True)
    cands = []
    for length in dict.fromkeys(small + [length for _, length in lengths[:3]]):
        for lang in ("en", "es"):
            key = _key_for_length(letters, length, lang)
            # reducir claves repetidas ("abcabc" -> "abc")
            for sub in range(1, len(key) + 1):
                if len(key) % sub == 0 and key[:sub] * (len(key) // sub) == key:
                    key = key[:sub]
                    break
            cands.append((f"Vigenère (clave '{key.upper()}')", _vigenere_decrypt(text, key)))
    uniq = list(dict(cands).items())
    return _best(uniq, 1)


@decoder("Rail Fence (fuerza bruta)", "cipher")
def rail_fence(data: bytes):
    text = as_text(data)
    if not text or len(text) < 8 or len(text) > 5000:
        return []
    cands = []
    n = len(text)
    for rails in range(2, min(12, n // 2)):
        pattern = list(range(rails)) + list(range(rails - 2, 0, -1))
        order = sorted(range(n), key=lambda i: (pattern[i % len(pattern)], i))
        out = [""] * n
        for ch, pos in zip(text, order):
            out[pos] = ch
        cands.append((f"Rail Fence ({rails} rieles)", "".join(out)))
    return _best(cands, 1)


@decoder("Escítala / columnas (fuerza bruta)", "cipher")
def scytale(data: bytes):
    text = as_text(data)
    if not text or len(text) < 10 or len(text) > 5000:
        return []
    n = len(text)
    cands = []
    for cols in range(2, min(15, n // 2)):
        rows = -(-n // cols)
        out = "".join(text[r::rows] for r in range(rows))
        cands.append((f"Escítala ({cols} columnas)", out))
    return _best(cands, 1)


@decoder("Texto invertido", "cipher")
def reverse(data: bytes):
    text = as_text(data)
    if not text or len(text) < 4:
        return []
    return [("Invertir", text[::-1].encode())]


@decoder("Morse", "encoding")
def morse(data: bytes):
    text = as_text(data)
    if not text or not MORSE_RE.match(text.strip()) or not re.search(r"[.\-_·•]", text):
        return []
    norm = text.strip().replace("_", "-").replace("·", ".").replace("•", ".")
    words = re.split(r"\s*[/|]\s*|\s{2,}", norm)
    out_words = []
    for w in words:
        letters = []
        for code in w.split():
            if code not in MORSE:
                return []
            letters.append(MORSE[code])
        out_words.append("".join(letters))
    return [("Morse", " ".join(out_words).encode())]


@decoder("Bacon", "encoding")
def bacon(data: bytes):
    text = as_text(data)
    if not text:
        return []
    s = re.sub(r"\s+", "", text)
    if len(s) < 10 or len(s) % 5:
        return []
    alphabet26 = LOWER
    alphabet24 = "abcdefghiklmnopqrstuwxyz"  # I=J, U=V
    pairs = []
    if set(s.upper()) <= {"A", "B"}:
        pairs.append(s.upper().replace("A", "0").replace("B", "1"))
    elif set(s) <= {"0", "1"}:
        pairs.append(s)
    else:
        return []
    out = []
    for bits in pairs:
        for alpha, name in ((alphabet26, "26 letras"), (alphabet24, "24 letras")):
            chars = []
            for i in range(0, len(bits), 5):
                v = int(bits[i : i + 5], 2)
                if v >= len(alpha):
                    break
                chars.append(alpha[v])
            else:
                out.append((f"Bacon ({name})", "".join(chars).upper()))
    return _best(out, 1)


@decoder("A1Z26 (números a letras)", "encoding")
def a1z26(data: bytes):
    text = as_text(data)
    if not text or not re.fullmatch(r"\s*\d{1,2}(?:[\s,\-]+\d{1,2})+\s*(?:[/|]\s*\d{1,2}(?:[\s,\-]+\d{1,2})*\s*)*", text):
        return []
    words = re.split(r"\s*[/|]\s*", text.strip())
    out = []
    for w in words:
        nums = [int(n) for n in re.split(r"[\s,\-]+", w.strip()) if n]
        if any(n < 1 or n > 26 for n in nums):
            return []
        out.append("".join(UPPER[n - 1] for n in nums))
    return [("A1Z26", " ".join(out).encode())]


@decoder("Polybius / Tap code", "encoding")
def polybius(data: bytes):
    text = as_text(data)
    if not text:
        return []
    s = re.sub(r"[\s,]", "", text)
    if len(s) < 4 or len(s) % 2 or not re.fullmatch(r"[1-5]+", s):
        return []
    square = "ABCDEFGHIKLMNOPQRSTUVWXYZ"  # I/J juntas
    tap = "ABCDEFGHIJLMNOPQRSTUVWXYZ"  # C/K juntas
    out = []
    for grid, name in ((square, "Polybius"), (tap, "Tap code")):
        chars = [grid[(int(s[i]) - 1) * 5 + int(s[i + 1]) - 1] for i in range(0, len(s), 2)]
        out.append((name, "".join(chars)))
    return _best(out, 1)


T9 = {
    "2": "A", "22": "B", "222": "C", "3": "D", "33": "E", "333": "F",
    "4": "G", "44": "H", "444": "I", "5": "J", "55": "K", "555": "L",
    "6": "M", "66": "N", "666": "O", "7": "P", "77": "Q", "777": "R",
    "7777": "S", "8": "T", "88": "U", "888": "V", "9": "W", "99": "X",
    "999": "Y", "9999": "Z", "0": " ",
}


@decoder("Teclado de móvil (multi-tap)", "encoding")
def multitap(data: bytes):
    text = as_text(data)
    if not text or not re.fullmatch(r"[0-9]+(?:\s+[0-9]+)+", text.strip()):
        return []
    groups = text.split()
    if any(g not in T9 for g in groups):
        return []
    return [("Multi-tap", "".join(T9[g] for g in groups).encode())]
