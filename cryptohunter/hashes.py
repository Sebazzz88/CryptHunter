"""Identificación de hashes.

Un hash es una función de un solo sentido: no se puede "descifrar". Lo único
que tiene sentido es:

  1. Decir qué tipo de hash parece ser (por longitud y formato).
  2. Darle al usuario el comando listo para intentar recuperarlo con la
     herramienta que prefiera (hashcat, John the Ripper, etc.), que trabajan
     por diccionario o fuerza bruta, no "descifrando" el hash.

Este módulo solo identifica y arma comandos; no ejecuta nada.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass(frozen=True)
class HashType:
    name: str
    hashcat_mode: str | None = None  # -m de hashcat
    john_format: str | None = None  # --format de John the Ripper
    note: str = ""


@dataclass
class HashMatch:
    text: str
    candidates: list[HashType] = field(default_factory=list)


# Cada patrón puede coincidir con varios tipos de hash de la misma longitud:
# por eso se devuelven como "candidatos", no como una única respuesta.
_RULES: list[tuple[re.Pattern[str], list[HashType]]] = [
    (re.compile(r"^\$2[abxy]?\$\d{2}\$[./A-Za-z0-9]{53}$"), [
        HashType("bcrypt", "3200", "bcrypt"),
    ]),
    (re.compile(r"^\$argon2(id|i|d)\$"), [
        HashType("Argon2", None, "argon2", "soportado en versiones recientes de hashcat/John"),
    ]),
    (re.compile(r"^\$1\$[./A-Za-z0-9]{1,8}\$[./A-Za-z0-9]{22}$"), [
        HashType("MD5-crypt (Unix)", "500", "md5crypt"),
    ]),
    (re.compile(r"^\$5\$"), [HashType("SHA-256-crypt (Unix)", "7400", "sha256crypt")]),
    (re.compile(r"^\$6\$"), [HashType("SHA-512-crypt (Unix)", "1800", "sha512crypt")]),
    (re.compile(r"^\$y\$"), [HashType("yescrypt (Unix)", None, None, "común en /etc/shadow de Linux moderno")]),
    (re.compile(r"^[a-fA-F0-9]{8}$"), [
        HashType("CRC32", "11500", None, "checksum, no criptográfico"),
        HashType("Adler-32", None, None, "checksum, no criptográfico"),
    ]),
    (re.compile(r"^[a-fA-F0-9]{16}$"), [
        HashType("MySQL 3.x (323)", "200", "mysql"),
        HashType("Half MD5", None, None),
    ]),
    (re.compile(r"^[a-fA-F0-9]{32}$"), [
        HashType("MD5", "0", "raw-md5"),
        HashType("MD4", "900", "raw-md4"),
        HashType("NTLM", "1000", "nt", "hash de contraseñas de Windows"),
        HashType("LM", "3000", "lm", "hash de Windows heredado"),
        HashType("MD5(MD5()) / doble MD5", "2600", None),
    ]),
    (re.compile(r"^[a-fA-F0-9]{40}$"), [
        HashType("SHA-1", "100", "raw-sha1"),
        HashType("RIPEMD-160", "6000", "ripemd-160"),
        HashType("MySQL 4.1+ (sin el *)", "300", "mysql-sha1"),
    ]),
    (re.compile(r"^\*[A-F0-9]{40}$"), [
        HashType("MySQL 4.1+ (con *)", "300", "mysql-sha1"),
    ]),
    (re.compile(r"^[a-fA-F0-9]{56}$"), [
        HashType("SHA-224", "1300", "raw-sha224"),
        HashType("SHA3-224", "17300", None),
    ]),
    (re.compile(r"^[a-fA-F0-9]{64}$"), [
        HashType("SHA-256", "1400", "raw-sha256"),
        HashType("SHA3-256", "17400", None),
        HashType("BLAKE2s-256", None, None),
    ]),
    (re.compile(r"^[a-fA-F0-9]{96}$"), [
        HashType("SHA-384", "10800", "raw-sha384"),
        HashType("SHA3-384", "17500", None),
    ]),
    (re.compile(r"^[a-fA-F0-9]{128}$"), [
        HashType("SHA-512", "1700", "raw-sha512"),
        HashType("SHA3-512", "17600", None),
        HashType("BLAKE2b-512", "600", "blake2b"),
        HashType("Whirlpool", "6100", "whirlpool"),
    ]),
    (re.compile(r"^[a-fA-F0-9]{32}:[a-fA-F0-9]{32}$"), [
        HashType("NTLM con salt / md5($pass.$salt)", "10", None),
    ]),
    (re.compile(r"^[a-fA-F0-9]{32}:.{1,30}$"), [
        HashType("md5($pass.$salt)", "10", None),
        HashType("md5($salt.$pass)", "20", None),
    ]),
    (re.compile(r"^\$NT\$[a-fA-F0-9]{32}$"), [HashType("NTLM", "1000", "nt")]),
    (re.compile(r"^[a-fA-F0-9]{32}\$[a-fA-F0-9]{32}$"), [
        HashType("vBulletin / md5(md5($pass).$salt)", "2611", None),
    ]),
    (re.compile(r"^{SHA}[A-Za-z0-9+/]{27}=$"), [HashType("SHA-1 Base64 (LDAP {SHA})", "101", "nsldap")]),
    (re.compile(r"^{SSHA}[A-Za-z0-9+/]+=*$"), [HashType("SSHA Base64 (LDAP {SSHA})", "111", "nsldaps")]),
    (re.compile(r"^sha256\$[A-Za-z0-9]+\$[a-fA-F0-9]{64}$"), [
        HashType("Django (PBKDF2-SHA256)", "10000", "django"),
    ]),
    (re.compile(r"^pbkdf2_sha256\$"), [HashType("Django PBKDF2-SHA256", "10000", "django")]),
    (re.compile(r"^\$pbkdf2-sha256\$"), [HashType("PBKDF2-HMAC-SHA256", "10900", "pbkdf2-hmac-sha256")]),
    (re.compile(r"^\$P\$[./A-Za-z0-9]{31}$"), [
        HashType("phpass (WordPress/phpBB)", "400", "phpass"),
    ]),
    (re.compile(r"^\$H\$[./A-Za-z0-9]{31}$"), [HashType("phpass (phpBB3)", "400", "phpass")]),
    (re.compile(r"^[a-fA-F0-9]{130}$"), [HashType("Keccak-512 / otras variantes de 520 bits", None, None)]),
    (re.compile(r"^[a-fA-F0-9]{16}:[0-9]{1,}$"), [HashType("Oracle 11g", "112", "oracle11c")]),
]


def identify(text: str) -> HashMatch | None:
    s = text.strip()
    if " " in s or "\n" in s:
        return None
    for pattern, types in _RULES:
        if pattern.match(s):
            return HashMatch(s, types)
    return None


# --- Comandos para herramientas externas --------------------------------------
# Plantillas con marcadores {hash_file}, {wordlist}, {mode}, {format}.
# La herramienta no ejecuta nada: solo muestra el comando para que el usuario lo
# corra en su propio equipo con la herramienta que prefiera.

TOOLS: dict[str, dict] = {
    "hashcat": {
        "label": "hashcat",
        "field": "hashcat_mode",
        "needs": "modo -m",
        "diccionario": "hashcat -m {mode} -a 0 {hash_file} {wordlist}",
        "fuerza_bruta": "hashcat -m {mode} -a 3 {hash_file} ?a?a?a?a?a?a",
        "url": "https://hashcat.net/hashcat/",
    },
    "john": {
        "label": "John the Ripper",
        "field": "john_format",
        "needs": "--format",
        "diccionario": "john --format={format} --wordlist={wordlist} {hash_file}",
        "fuerza_bruta": "john --format={format} --incremental {hash_file}",
        "url": "https://www.openwall.com/john/",
    },
    "name-that-hash": {
        "label": "Name-That-Hash (solo identificar)",
        "field": None,
        "needs": None,
        "identificar": "nth --text '{hash}'",
        "url": "https://github.com/HashPals/Name-That-Hash",
    },
    "hashid": {
        "label": "hashid (solo identificar)",
        "field": None,
        "needs": None,
        "identificar": "hashid '{hash}'",
        "url": "https://github.com/psypanda/hashID",
    },
}

DEFAULT_WORDLIST = "/usr/share/wordlists/rockyou.txt"


def commands_for(
    match: HashMatch,
    tool: str = "hashcat",
    candidate_index: int = 0,
    wordlist: str = DEFAULT_WORDLIST,
    hash_file: str = "hash.txt",
) -> dict:
    """Devuelve los comandos sugeridos para una herramienta y un candidato."""
    tool = tool.lower()
    spec = TOOLS.get(tool)
    if spec is None:
        return {"error": f"herramienta desconocida: {tool}"}
    ht = match.candidates[candidate_index] if match.candidates else HashType("?")
    out: dict = {"tool": spec["label"], "hash_type": ht.name, "url": spec["url"], "commands": {}}

    field = spec["field"]
    value = getattr(ht, field) if field else None
    if field and value is None:
        out["commands"] = {}
        out["unsupported"] = f"{spec['label']} no tiene un {spec['needs']} conocido para {ht.name}."
        return out

    fmt = {
        "hash": match.text,
        "hash_file": hash_file,
        "wordlist": wordlist,
        "mode": value,
        "format": value,
    }
    for key, template in spec.items():
        if key in ("label", "field", "needs", "url"):
            continue
        out["commands"][key] = template.format(**fmt)
    return out
