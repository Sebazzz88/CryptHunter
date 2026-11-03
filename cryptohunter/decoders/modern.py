"""XOR, compresión, JWT y lenguajes esotéricos."""

from __future__ import annotations

import base64
import bz2
import gzip
import json
import lzma
import re
import zlib

from .. import scoring
from ..registry import as_text, as_text_lossy, decoder


def _byte_score(data: bytes) -> float:
    """Puntuación rápida para bytes (frecuencia de letras inglés/español + espacios)."""
    if not data:
        return 0.0
    common = b"etaoinshrdlucmfwypvbgkjqxz"
    total = 0.0
    for b in data:
        if b == 32:
            total += 2.0
        elif 97 <= b <= 122:
            total += 1.0 + (26 - common.index(b)) / 26
        elif 65 <= b <= 90:
            total += 0.8
        elif 48 <= b <= 57 or b in b".,'!?-_{}\n":
            total += 0.4
        elif b < 32 or b > 126:
            total -= 2.0
    return total / len(data)


def _is_mostly_printable(data: bytes) -> bool:
    return sum(32 <= b <= 126 or b in (9, 10, 13) for b in data) / max(1, len(data)) > 0.95


@decoder("XOR de un byte (fuerza bruta)", "cipher")
def xor_single(data: bytes):
    if len(data) < 4 or len(data) > 100_000:
        return []
    ranked = sorted(range(1, 256), key=lambda k: _byte_score(bytes(b ^ k for b in data)), reverse=True)
    out = []
    for k in ranked[:2]:
        plain = bytes(b ^ k for b in data)
        if _is_mostly_printable(plain):
            out.append((f"XOR (clave 0x{k:02x} '{chr(k) if 32 < k < 127 else '?'}')", plain))
    return out


def _hamming(a: bytes, b: bytes) -> int:
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b))


@decoder("XOR con clave repetida (Hamming)", "cipher")
def xor_repeating(data: bytes):
    if len(data) < 40 or _is_mostly_printable(data):
        return []
    sizes = []
    for ks in range(2, min(41, len(data) // 4)):
        blocks = [data[i * ks : (i + 1) * ks] for i in range(min(8, len(data) // ks))]
        dists = [_hamming(blocks[i], blocks[i + 1]) / ks for i in range(len(blocks) - 1)]
        sizes.append((sum(dists) / len(dists), ks))
    sizes.sort()
    out = []
    for _, ks in sizes[:3]:
        key = bytes(
            max(range(256), key=lambda k: _byte_score(bytes(b ^ k for b in data[i::ks])))
            for i in range(ks)
        )
        plain = bytes(b ^ key[i % ks] for i, b in enumerate(data))
        if _is_mostly_printable(plain):
            out.append((f"XOR repetido (clave {key!r})", plain))
    out.sort(key=lambda kv: scoring.score(as_text_lossy(kv[1])), reverse=True)
    return out[:1]


@decoder("Gzip", "compression")
def gunzip(data: bytes):
    if not data.startswith(b"\x1f\x8b"):
        return []
    try:
        return [("Gzip", gzip.decompress(data))]
    except (OSError, EOFError, zlib.error):
        return []


@decoder("Zlib / Deflate", "compression")
def unzlib(data: bytes):
    out = []
    if len(data) > 2 and data[0] == 0x78:
        try:
            out.append(("Zlib", zlib.decompress(data)))
        except zlib.error:
            pass
    if not out and len(data) > 4 and not _is_mostly_printable(data):
        try:
            raw = zlib.decompress(data, -15)
            if raw:
                out.append(("Raw Deflate", raw))
        except zlib.error:
            pass
    return out


@decoder("Bzip2", "compression")
def unbz2(data: bytes):
    if not data.startswith(b"BZh"):
        return []
    try:
        return [("Bzip2", bz2.decompress(data))]
    except (OSError, ValueError):
        return []


@decoder("LZMA / XZ", "compression")
def unlzma(data: bytes):
    if not (data.startswith(b"\xfd7zXZ") or data.startswith(b"\x5d\x00\x00")):
        return []
    try:
        return [("LZMA/XZ", lzma.decompress(data))]
    except lzma.LZMAError:
        return []


JWT_RE = re.compile(r"^eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*$")


@decoder("JWT", "encoding")
def jwt(data: bytes):
    text = as_text(data)
    if not text or not JWT_RE.match(text.strip()):
        return []
    parts = text.strip().split(".")
    try:
        header, payload = (
            json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4))) for p in parts[:2]
        )
    except (ValueError, json.JSONDecodeError):
        return []
    pretty = json.dumps({"header": header, "payload": payload}, indent=2, ensure_ascii=False)
    return [("JWT (header + payload)", pretty.encode())]


def run_brainfuck(code: str, max_steps: int = 2_000_000) -> str | None:
    code = "".join(c for c in code if c in "+-<>[].,")
    stack, jumps = [], {}
    for i, c in enumerate(code):
        if c == "[":
            stack.append(i)
        elif c == "]":
            if not stack:
                return None
            j = stack.pop()
            jumps[i], jumps[j] = j, i
    if stack:
        return None
    tape, ptr, pc, steps, out = [0] * 30000, 0, 0, 0, []
    while pc < len(code) and steps < max_steps:
        c = code[pc]
        if c == "+":
            tape[ptr] = (tape[ptr] + 1) % 256
        elif c == "-":
            tape[ptr] = (tape[ptr] - 1) % 256
        elif c == ">":
            ptr = (ptr + 1) % 30000
        elif c == "<":
            ptr = (ptr - 1) % 30000
        elif c == ".":
            out.append(chr(tape[ptr]))
        elif c == "[" and tape[ptr] == 0:
            pc = jumps[pc]
        elif c == "]" and tape[ptr] != 0:
            pc = jumps[pc]
        pc += 1
        steps += 1
    return "".join(out)


@decoder("Brainfuck", "esoteric")
def brainfuck(data: bytes):
    text = as_text(data)
    if not text:
        return []
    core = re.sub(r"\s", "", text)
    if len(core) < 10 or not re.fullmatch(r"[+\-<>\[\].,]+", core) or "." not in core:
        return []
    result = run_brainfuck(core)
    return [("Brainfuck", result.encode("latin-1", "replace"))] if result else []


@decoder("Ook!", "esoteric")
def ook(data: bytes):
    text = as_text(data)
    if not text or "Ook" not in text:
        return []
    tokens = re.findall(r"Ook([.!?])", text)
    if len(tokens) < 4 or len(tokens) % 2:
        return []
    table = {
        ".?": ">", "?.": "<", "..": "+", "!!": "-",
        "!.": ".", ".!": ",", "!?": "[", "?!": "]",
    }
    bf = "".join(table.get(tokens[i] + tokens[i + 1], "") for i in range(0, len(tokens), 2))
    result = run_brainfuck(bf)
    return [("Ook!", result.encode("latin-1", "replace"))] if result else []
