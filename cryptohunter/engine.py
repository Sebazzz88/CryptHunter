"""Motor de detección automática.

Hace una búsqueda en haz (beam search): aplica todos los decodificadores al
texto, puntúa cada resultado y sigue decodificando los mejores candidatos
hasta ``max_depth`` capas. Así detecta cadenas como
Base64 -> Hex -> ROT13 sin que el usuario elija nada.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from . import decoders  # noqa: F401  (registra los decodificadores)
from . import scoring
from .registry import DECODERS, as_text, as_text_lossy

CIPHER_PENALTY = 0.05
MAX_CIPHER_STEPS = 2
ACCEPT_SCORE = 0.45


@dataclass
class Node:
    data: bytes
    chain: list[str] = field(default_factory=list)
    kinds: list[str] = field(default_factory=list)

    @property
    def text(self) -> str:
        return as_text_lossy(self.data)

    @property
    def score(self) -> float:
        # penalización por cada capa extra: preferimos la explicación más simple.
        # Los cifrados por fuerza bruta penalizan más porque siempre "producen algo".
        base = scoring.score(self.text)
        if as_text(self.data) is None:
            base *= 0.3  # no es UTF-8 válido: casi seguro son bytes binarios
        return base - sum(CIPHER_PENALTY if k == "cipher" else 0.01 for k in self.kinds)

    @property
    def cipher_steps(self) -> int:
        return self.kinds.count("cipher")


@dataclass
class Report:
    input: str
    best: Node | None
    candidates: list[Node]

    @property
    def solved(self) -> bool:
        return self.best is not None and bool(self.best.chain)


def _expand(node: Node) -> list[Node]:
    children = []
    # las transformaciones que se anulan (ROT13 dos veces, invertir dos veces...)
    # vuelven a un texto ya visto y se descartan con el conjunto `seen`
    for dec in DECODERS:
        if dec.category == "cipher" and node.cipher_steps >= MAX_CIPHER_STEPS:
            continue
        try:
            results = dec.func(node.data)
        except Exception:  # un decodificador defectuoso no debe tumbar la búsqueda
            continue
        for label, out in results:
            if out and out != node.data:
                children.append(Node(out, node.chain + [label], node.kinds + [dec.category]))
    return children


def analyze(text: str, max_depth: int = 6, beam_width: int = 25, top: int = 5) -> Report:
    root = Node(text.strip().encode("utf-8"))
    seen = {root.data}
    frontier = [root]
    all_nodes = [root]

    for _ in range(max_depth):
        children = []
        for node in frontier:
            for child in _expand(node):
                if child.data in seen or len(child.data) == 0:
                    continue
                seen.add(child.data)
                children.append(child)
        if not children:
            break
        children.sort(key=lambda n: n.score, reverse=True)
        # las codificaciones estrictas (Base64, Hex, ...) casi nunca dan falsos
        # positivos, así que siempre se exploran aunque su salida aún no sea legible
        frontier = children[:beam_width]
        frontier += [n for n in children[beam_width:] if n.kinds[-1] != "cipher"][:beam_width]
        all_nodes.extend(frontier)

    ranked = sorted(all_nodes, key=lambda n: n.score, reverse=True)
    best = ranked[0]
    root_score = root.score
    # solo aceptamos una decodificación si mejora claramente al original
    if best is not root and best.score < max(ACCEPT_SCORE, root_score + 0.05):
        best = root
    uniq, texts = [], set()
    for n in ranked:
        if n.text not in texts and n.chain:
            texts.add(n.text)
            uniq.append(n)
        if len(uniq) >= top:
            break
    return Report(text, best, uniq)
