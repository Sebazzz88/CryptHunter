"""Formatos que se reconocen pero no se descifran aquí.

Son cosas como bloques PEM, claves SSH o UUID: no son texto cifrado que esta
herramienta pueda devolver en claro, pero conviene decirle al usuario qué son.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class FormatInfo:
    name: str
    note: str


_RULES: list[tuple[re.Pattern[str], FormatInfo]] = [
    (re.compile(r"^-----BEGIN ([A-Z0-9 ]+)-----", re.M),
     FormatInfo("Bloque PEM", "clave o certificado codificado en Base64 (DER)")),
    (re.compile(r"^ssh-(rsa|ed25519|dss) |^ecdsa-sha2-"),
     FormatInfo("Clave pública SSH", "clave pública, no hay nada que descifrar")),
    (re.compile(r"^U2FsdGVkX1"),
     FormatInfo("OpenSSL 'Salted__'", "cifrado AES/DES con contraseña: necesita la clave (openssl enc -d)")),
    (re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"),
     FormatInfo("UUID", "identificador único, no es texto cifrado")),
    (re.compile(r"^-----BEGIN PGP MESSAGE-----", re.M),
     FormatInfo("Mensaje PGP/GPG", "necesita la clave privada (gpg -d)")),
]


def identify(text: str) -> FormatInfo | None:
    s = text.strip()
    for pattern, info in _RULES:
        if pattern.search(s):
            return info
    return None
