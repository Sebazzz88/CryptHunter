"""Puntuación de "qué tan legible" es un texto.

Se combinan varias señales:
  * proporción de caracteres imprimibles
  * parecido de la frecuencia de letras con inglés / español
  * cantidad de palabras comunes reconocidas
  * proporción de espacios y letras

El resultado es un número aproximadamente entre 0 y 1.
"""

from __future__ import annotations

import math
import re
import string
import unicodedata

ENGLISH_FREQ = {
    "a": 8.167, "b": 1.492, "c": 2.782, "d": 4.253, "e": 12.702, "f": 2.228,
    "g": 2.015, "h": 6.094, "i": 6.966, "j": 0.153, "k": 0.772, "l": 4.025,
    "m": 2.406, "n": 6.749, "o": 7.507, "p": 1.929, "q": 0.095, "r": 5.987,
    "s": 6.327, "t": 9.056, "u": 2.758, "v": 0.978, "w": 2.360, "x": 0.150,
    "y": 1.974, "z": 0.074,
}

SPANISH_FREQ = {
    "a": 12.53, "b": 1.42, "c": 4.68, "d": 5.86, "e": 13.68, "f": 0.69,
    "g": 1.01, "h": 0.70, "i": 6.25, "j": 0.44, "k": 0.02, "l": 4.97,
    "m": 3.15, "n": 6.71, "o": 8.68, "p": 2.51, "q": 0.88, "r": 6.87,
    "s": 7.98, "t": 4.63, "u": 3.93, "v": 0.90, "w": 0.01, "x": 0.22,
    "y": 0.90, "z": 0.52,
}

LANGUAGES = {"en": ENGLISH_FREQ, "es": SPANISH_FREQ}

COMMON_WORDS = set("""
the be to of and a in that have i it for not on with he as you do at this but
his by from they we say her she or an will my one all would there their what
so up out if about who get which go me when make can like time no just him
know take people into year your good some could them see other than then now
look only come its over think also back after use two how our work first well
way even new want because any these give day most us is are was were has had
been hello world secret password key message text code cipher hidden
answer welcome congratulations found this here test example quick brown fox
jumps lazy dog
el la de que y a en un ser se no haber por con su para como estar tener le lo
todo pero mas hacer o poder decir este ir otro ese si me ya ver porque dar
cuando muy sin vez mucho saber que sobre mi alguno mismo yo tambien hasta ano
dos querer entre asi primero desde grande eso ni nos llegar pasar tiempo ella
del los las una al es son esta hola mundo mensaje secreto clave contrasena
bandera texto codigo cifrado oculto respuesta bienvenido felicidades
encontraste aqui prueba ejemplo
attack dawn meet tonight morning night day week money bank send help please
thank thanks name user admin login access data file open close start stop
where why yes from more very must should never always every each many much
said made find long little great right still own last place same before
through between under again around while world life hand part child woman
man men women house school country home small large next early young old
important public bad able
casa vida dia noche hombre mujer ano trabajo parte pais ciudad gracias nunca
siempre cada donde mientras porque ahora antes despues bueno malo nuevo viejo
hoy manana ayer seguridad informacion sistema usuario nombre ataque reunion
herramienta probar cifrar descifrar
""".split())

WORD_RE = re.compile(r"[a-z]+")


_ACCENTED = "áéíóúüñàèìòùâêîôûçÁÉÍÓÚÜÑÀÈÌÒÙÂÊÎÔÛÇ"
_ACCENT_TABLE = str.maketrans(
    _ACCENTED,
    "".join(unicodedata.normalize("NFKD", c)[0] for c in _ACCENTED),
)


def strip_accents(text: str) -> str:
    # solo vocales acentuadas, ñ y ç habituales: otros símbolos (º, ², Þ...) no
    # deben convertirse en letras porque suelen venir de bytes basura
    return text.translate(_ACCENT_TABLE)


def printable_ratio(text: str) -> float:
    if not text:
        return 0.0
    ok = sum(1 for c in text if c.isprintable() or c in "\n\r\t")
    return ok / len(text)


def letter_fit(text: str) -> float:
    """0..1 según qué tan parecida es la distribución de letras a un idioma."""
    letters = [c for c in strip_accents(text.lower()) if "a" <= c <= "z"]
    n = len(letters)
    if n < 4:
        return 0.0
    counts = {c: 0 for c in string.ascii_lowercase}
    for c in letters:
        counts[c] += 1
    best = 0.0
    for freq in LANGUAGES.values():
        dot = sum(counts[c] * freq[c] for c in counts)
        norm_o = math.sqrt(sum(v * v for v in counts.values()))
        norm_e = math.sqrt(sum(v * v for v in freq.values()))
        cos = dot / (norm_o * norm_e)
        best = max(best, cos)
    # texto aleatorio uniforme ronda 0.75; texto natural > 0.9
    fit = (best - 0.72) / 0.23
    # textos cortos dan frecuencias poco fiables
    confidence = min(1.0, n / 20)
    return max(0.0, min(1.0, fit)) * confidence


def chi_squared(text: str, lang: str = "en") -> float:
    freq = LANGUAGES[lang]
    letters = [c for c in strip_accents(text.lower()) if "a" <= c <= "z"]
    n = len(letters)
    if n == 0:
        return float("inf")
    counts = {c: 0 for c in string.ascii_lowercase}
    for c in letters:
        counts[c] += 1
    total = 0.0
    for c, f in freq.items():
        expected = n * f / 100
        total += (counts[c] - expected) ** 2 / expected
    return total


def _token_coverage(token: str) -> int:
    if len(token) <= 2:
        return len(token) if token in COMMON_WORDS else 0
    covered = [False] * len(token)
    for i in range(len(token)):
        for length in range(min(14, len(token) - i), 2, -1):
            if token[i : i + length] in COMMON_WORDS:
                for j in range(i, i + length):
                    covered[j] = True
                break
    return sum(covered)


def word_score(text: str) -> float:
    """Fracción de letras cubiertas por palabras comunes.

    Dentro de cada palabra se buscan palabras conocidas de 3+ letras como
    subcadenas, así también funciona sin espacios ("thequickbrownfox").
    Las de 1-2 letras solo cuentan si aparecen sueltas.
    """
    tokens = WORD_RE.findall(strip_accents(text.lower()))
    n = sum(len(t) for t in tokens)
    if not n:
        return 0.0
    return min(1.0, 1.25 * sum(_token_coverage(t) for t in tokens) / n)


NORMAL_PUNCT = set(" .,;:!?¿¡'\"-()\n\r\t")


def symbol_ratio(text: str) -> float:
    """Proporción de símbolos raros (ni letras, ni dígitos, ni puntuación normal)."""
    if not text:
        return 0.0
    return sum(1 for c in text if not c.isalnum() and c not in NORMAL_PUNCT) / len(text)


def space_fit(text: str) -> float:
    if len(text) < 8:
        return 0.5
    ratio = text.count(" ") / len(text)
    # el texto natural tiene ~12-20% de espacios
    return max(0.0, 1 - abs(ratio - 0.16) / 0.16)


def alpha_ratio(text: str) -> float:
    if not text:
        return 0.0
    return sum(1 for c in text if c.isalpha() or c == " ") / len(text)


def score(text: str) -> float:
    """Puntuación global de legibilidad."""
    if not text or not text.strip():
        return 0.0
    pr = printable_ratio(text)
    if pr < 0.85:
        return pr * 0.1
    words = word_score(text)
    s = (
        0.55 * words
        # una buena frecuencia de letras sin palabras reales no basta
        + 0.25 * letter_fit(text) * min(1.0, 2 * words)
        + 0.10 * space_fit(text)
        + 0.10 * alpha_ratio(text)
    )
    s *= pr ** 3
    # el texto natural casi no tiene símbolos como < ^ ] ` ~ |
    s *= max(0.0, 1 - 4 * symbol_ratio(text))
    return s


def looks_like_plaintext(text: str) -> bool:
    return score(text) >= 0.55
