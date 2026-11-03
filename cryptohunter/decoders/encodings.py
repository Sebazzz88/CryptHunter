"""Codificaciones (no son cifrados con clave, solo representaciones)."""

from __future__ import annotations

import base64
import binascii
import html
import quopri
import re
import urllib.parse

from ..registry import as_text, decoder

B64_RE = re.compile(r"^[A-Za-z0-9+/\s]+={0,2}\s*$")
B64URL_RE = re.compile(r"^[A-Za-z0-9_\-\s]+={0,2}\s*$")
B32_RE = re.compile(r"^[A-Z2-7\s]+=*\s*$")
B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
B58_RE = re.compile(f"^[{B58_ALPHABET}]+$")
B62_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
B45_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"
HEX_RE = re.compile(r"^(?:0x|\\x)?[0-9a-fA-F]{2}(?:[\s:,\-]*(?:0x|\\x)?[0-9a-fA-F]{2})*$")
BIN_RE = re.compile(r"^[01\s]+$")
OCT_RE = re.compile(r"^[0-7]{1,3}(?:[\s,]+[0-7]{1,3})+$")
DEC_RE = re.compile(r"^\d{1,3}(?:[\s,]+\d{1,3})+$")
BIGINT_RE = re.compile(r"^\d{6,}$")
URL_RE = re.compile(r"%[0-9a-fA-F]{2}")
HTML_RE = re.compile(r"&(?:#\d+|#x[0-9a-fA-F]+|[a-zA-Z]+);")
UNI_RE = re.compile(r"\\u[0-9a-fA-F]{4}|\\U[0-9a-fA-F]{8}|\\x[0-9a-fA-F]{2}|\\[0-7]{3}")
QP_RE = re.compile(r"=[0-9A-F]{2}")


def _clean(text: str) -> str:
    return re.sub(r"\s+", "", text)


@decoder("Base64")
def base64_decode(data: bytes):
    text = as_text(data)
    if not text or len(_clean(text)) < 4 or not B64_RE.match(text):
        return []
    s = _clean(text)
    if len(s.rstrip("=")) % 4 == 1:
        return []
    s += "=" * (-len(s) % 4)
    try:
        return [("Base64", base64.b64decode(s, validate=True))]
    except (binascii.Error, ValueError):
        return []


@decoder("Base64 URL-safe")
def base64url_decode(data: bytes):
    text = as_text(data)
    if not text or not B64URL_RE.match(text) or not re.search(r"[-_]", text):
        return []
    s = _clean(text)
    s += "=" * (-len(s) % 4)
    try:
        return [("Base64 URL-safe", base64.urlsafe_b64decode(s))]
    except (binascii.Error, ValueError):
        return []


@decoder("Base32")
def base32_decode(data: bytes):
    text = as_text(data)
    if not text or len(_clean(text)) < 8 or not B32_RE.match(text):
        return []
    s = _clean(text)
    s += "=" * (-len(s) % 8)
    try:
        return [("Base32", base64.b32decode(s))]
    except (binascii.Error, ValueError):
        return []


@decoder("Base16 / Hex")
def hex_decode(data: bytes):
    text = as_text(data)
    if not text:
        return []
    text = text.strip()
    if not HEX_RE.match(text):
        return []
    s = re.sub(r"0x|\\x|[\s:,\-]", "", text)
    if len(s) % 2:
        return []
    try:
        return [("Hex", bytes.fromhex(s))]
    except ValueError:
        return []


@decoder("Base58")
def base58_decode(data: bytes):
    text = as_text(data)
    if not text:
        return []
    s = text.strip()
    if len(s) < 4 or not B58_RE.match(s):
        return []
    num = 0
    for c in s:
        num = num * 58 + B58_ALPHABET.index(c)
    raw = num.to_bytes((num.bit_length() + 7) // 8, "big") if num else b""
    pad = len(s) - len(s.lstrip("1"))
    return [("Base58", b"\x00" * pad + raw)]


@decoder("Base62")
def base62_decode(data: bytes):
    text = as_text(data)
    if not text:
        return []
    s = text.strip()
    if len(s) < 6 or not re.fullmatch(r"[0-9A-Za-z]+", s):
        return []
    num = 0
    for c in s:
        num = num * 62 + B62_ALPHABET.index(c)
    if not num:
        return []
    return [("Base62", num.to_bytes((num.bit_length() + 7) // 8, "big"))]


@decoder("Base85")
def base85_decode(data: bytes):
    text = as_text(data)
    if not text or len(text.strip()) < 5:
        return []
    s = text.strip()
    out = []
    a85 = s
    if a85.startswith("<~") and a85.endswith("~>"):
        a85 = a85[2:-2]
    try:
        out.append(("Ascii85", base64.a85decode(a85, adobe=False, ignorechars=b" \t\n\r")))
    except (ValueError, binascii.Error):
        pass
    try:
        out.append(("Base85 (RFC 1924)", base64.b85decode(_clean(s))))
    except (ValueError, binascii.Error):
        pass
    try:
        out.append(("Z85", base64.z85decode(_clean(s))))
    except (ValueError, binascii.Error, AttributeError):
        pass
    return out


@decoder("Base45")
def base45_decode(data: bytes):
    text = as_text(data)
    if not text:
        return []
    s = text.strip()
    if len(s) < 3 or any(c not in B45_ALPHABET for c in s) or len(s) % 3 == 1:
        return []
    if not re.search(r"[ $%*+\-./:]", s):
        return []
    out = bytearray()
    for i in range(0, len(s), 3):
        chunk = s[i : i + 3]
        vals = [B45_ALPHABET.index(c) for c in chunk]
        if len(vals) == 3:
            n = vals[0] + vals[1] * 45 + vals[2] * 2025
            if n > 0xFFFF:
                return []
            out += n.to_bytes(2, "big")
        else:
            n = vals[0] + vals[1] * 45
            if n > 0xFF:
                return []
            out.append(n)
    return [("Base45", bytes(out))]


@decoder("Binario")
def binary_decode(data: bytes):
    text = as_text(data)
    if not text or not BIN_RE.match(text):
        return []
    s = _clean(text)
    if len(s) < 8:
        return []
    out = []
    for width in (8, 7):
        if len(s) % width == 0:
            out.append(
                (f"Binario ({width} bits)", bytes(int(s[i : i + width], 2) for i in range(0, len(s), width)))
            )
    # grupos separados por espacios de largo variable
    groups = text.split()
    if len(groups) > 1 and not out:
        try:
            out.append(("Binario (grupos)", bytes(int(g, 2) for g in groups)))
        except ValueError:
            pass
    return out


@decoder("Octal")
def octal_decode(data: bytes):
    text = as_text(data)
    if not text or not OCT_RE.match(text.strip()):
        return []
    try:
        return [("Octal", bytes(int(g, 8) for g in re.split(r"[\s,]+", text.strip())))]
    except ValueError:
        return []


@decoder("Decimal (códigos ASCII)")
def decimal_decode(data: bytes):
    text = as_text(data)
    if not text or not DEC_RE.match(text.strip()):
        return []
    nums = [int(g) for g in re.split(r"[\s,]+", text.strip())]
    if any(n > 255 for n in nums):
        return []
    return [("Decimal ASCII", bytes(nums))]


@decoder("Entero grande -> bytes")
def bigint_decode(data: bytes):
    text = as_text(data)
    if not text or not BIGINT_RE.match(text.strip()):
        return []
    n = int(text.strip())
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return [("Entero -> bytes", raw)]


@decoder("URL encoding")
def url_decode(data: bytes):
    text = as_text(data)
    if not text or not URL_RE.search(text):
        return []
    return [("URL decode", urllib.parse.unquote_to_bytes(text.replace("+", " ")))]


@decoder("Entidades HTML")
def html_decode(data: bytes):
    text = as_text(data)
    if not text or not HTML_RE.search(text):
        return []
    return [("HTML entities", html.unescape(text).encode())]


@decoder("Escapes Unicode / \\x")
def unicode_escape_decode(data: bytes):
    text = as_text(data)
    if not text or not UNI_RE.search(text):
        return []
    try:
        decoded = text.encode("latin-1", "backslashreplace").decode("unicode_escape")
        return [("Unicode escapes", decoded.encode("utf-8", "surrogatepass"))]
    except (UnicodeDecodeError, UnicodeEncodeError):
        return []


@decoder("Quoted-Printable")
def qp_decode(data: bytes):
    text = as_text(data)
    if not text or len(QP_RE.findall(text)) < 2:
        return []
    return [("Quoted-Printable", quopri.decodestring(data))]


@decoder("UUencode")
def uu_decode(data: bytes):
    text = as_text(data)
    if not text:
        return []
    lines = text.strip().splitlines()
    if lines and lines[0].startswith("begin "):
        lines = lines[1:]
    elif not (lines and lines[0].startswith("M") and len(lines[0]) == 61):
        return []
    if lines and lines[-1].strip() == "end":
        lines = lines[:-1]
    if not lines:
        return []
    out = b""
    try:
        for line in lines:
            if line.strip() in ("`", ""):
                continue
            out += binascii.a2b_uu(line)
    except binascii.Error:
        return []
    return [("UUencode", out)] if out else []
