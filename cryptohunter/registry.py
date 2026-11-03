"""Registro central de decodificadores.

Cada decodificador recibe bytes y devuelve una lista de resultados
``(etiqueta, bytes_decodificados)``. Si no aplica, devuelve una lista vacía.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

Result = tuple[str, bytes]
DecoderFunc = Callable[[bytes], list[Result]]


@dataclass(frozen=True)
class Decoder:
    name: str
    category: str  # "encoding", "cipher", "compression", "esoteric"
    func: DecoderFunc


DECODERS: list[Decoder] = []


def decoder(name: str, category: str = "encoding"):
    def wrap(func: DecoderFunc) -> DecoderFunc:
        DECODERS.append(Decoder(name, category, func))
        return func

    return wrap


def as_text(data: bytes) -> str | None:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


def as_text_lossy(data: bytes) -> str:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("latin-1")
