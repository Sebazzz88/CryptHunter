"""Análisis de alto nivel organizado en secciones.

La herramienta tiene tres apartados, cada uno con su propia función y
descripción de lo que puede (y no puede) hacer:

  * "cifrado"        -> detecta y DESCIFRA automáticamente codificaciones y
                        cifrados clásicos (Base64, César, Vigenère, XOR...).
  * "hash"           -> solo DETECTA el tipo de hash y da el comando para
                        intentar recuperarlo con la herramienta que prefieras.
  * "identificacion" -> reconoce formatos (PEM, SSH, UUID...) que no son texto
                        cifrado que esta herramienta devuelva en claro.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

from . import formats, hashes
from .engine import analyze

SECTIONS = {
    "cifrado": {
        "titulo": "Cifrado y codificación",
        "resumen": "Detecta el cifrado y lo descifra automáticamente.",
        "descripcion": (
            "Pega un texto codificado o cifrado y la herramienta prueba todo sola, "
            "incluso varias capas encadenadas (p. ej. Base64 → Hex → ROT13), hasta "
            "devolverlo en claro. No tienes que elegir el tipo de cifrado."
        ),
        "puede": [
            "Codificaciones: Base64/32/58/62/85/45, Hex, binario, octal, decimal, URL, HTML, Unicode, Quoted-Printable, UUencode, JWT.",
            "Cifrados clásicos con o sin clave: César, ROT13/47, Atbash, Afín, Vigenère, Rail Fence, escítala, XOR.",
            "Alfabetos y códigos: Morse, Bacon, A1Z26, Polybius, Tap code, multi-tap.",
            "Compresión: Gzip, Zlib, Bzip2, LZMA/XZ. Esotéricos: Brainfuck, Ook!.",
        ],
        "no_puede": [
            "Cifrados modernos con clave (AES, RSA, ChaCha20...) sin la clave: eso va al apartado de identificación.",
        ],
    },
    "hash": {
        "titulo": "Hashes",
        "resumen": "Solo detecta el TIPO de hash (no se puede descifrar).",
        "descripcion": (
            "Un hash es una función de un solo sentido: NO se puede descifrar. Lo único "
            "posible es intentar recuperarlo por diccionario o fuerza bruta con una "
            "herramienta externa. Aquí se detecta de qué tipo parece ser y se te da el "
            "comando listo para la herramienta que prefieras; tú lo ejecutas en tu equipo."
        ),
        "puede": [
            "Identificar el tipo de hash por su longitud y formato (MD5, SHA-1/256/512, NTLM, bcrypt, Argon2, crypt de Unix, phpass, Django...).",
            "Darte el comando con el modo/formato correcto para hashcat o John the Ripper.",
            "Darte comandos de herramientas de solo identificación (Name-That-Hash, hashid).",
        ],
        "no_puede": [
            "Descifrar el hash: no existe forma de invertirlo.",
            "Ejecutar el ataque por ti: solo te muestra el comando.",
        ],
    },
    "identificacion": {
        "titulo": "Identificación de formatos",
        "resumen": "Reconoce formatos que no se descifran aquí.",
        "descripcion": (
            "Algunos textos no son cifrados que esta herramienta pueda abrir, pero se "
            "reconocen para decirte qué son y qué necesitarías para abrirlos."
        ),
        "puede": [
            "Reconocer bloques PEM, claves públicas SSH, mensajes PGP/GPG, OpenSSL 'Salted__' y UUID.",
        ],
        "no_puede": [
            "Descifrar claves o certificados: necesitas la clave privada o la contraseña con su herramienta (openssl, gpg...).",
        ],
    },
}


@dataclass
class ScanResult:
    input: str
    hash_match: hashes.HashMatch | None = None
    format_info: formats.FormatInfo | None = None
    cipher: object | None = None  # engine.Report
    sections_present: list[str] = field(default_factory=list)


def scan(text: str, decode: bool = True, max_depth: int = 6) -> ScanResult:
    """Analiza el texto y dice qué secciones aplican."""
    res = ScanResult(input=text)
    res.hash_match = hashes.identify(text)
    res.format_info = formats.identify(text)
    if decode:
        res.cipher = analyze(text, max_depth=max_depth)

    present = []
    if res.cipher is not None and res.cipher.solved:
        present.append("cifrado")
    if res.hash_match is not None:
        present.append("hash")
    if res.format_info is not None:
        present.append("identificacion")
    res.sections_present = present
    return res


def result_to_dict(res: ScanResult) -> dict:
    out: dict = {"input": res.input, "sections_present": res.sections_present, "sections": {}}
    if res.cipher is not None and res.cipher.solved:
        b = res.cipher.best
        out["sections"]["cifrado"] = {
            "chain": b.chain,
            "result": b.text,
            "candidates": [
                {"chain": n.chain, "score": round(n.score, 3), "result": n.text}
                for n in res.cipher.candidates
            ],
        }
    if res.hash_match is not None:
        out["sections"]["hash"] = {
            "candidates": [asdict(c) for c in res.hash_match.candidates],
            "tools": list(hashes.TOOLS),
        }
    if res.format_info is not None:
        out["sections"]["identificacion"] = asdict(res.format_info)
    return out
