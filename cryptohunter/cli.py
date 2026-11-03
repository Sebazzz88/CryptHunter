"""Interfaz de línea de comandos, organizada por secciones."""

from __future__ import annotations

import argparse
import json
import os
import sys

from . import __version__
from .hashes import commands_for
from .registry import DECODERS
from .scan import SECTIONS, result_to_dict, scan

# URL pública de rockyou.txt (el diccionario más usado) ya descomprimido.
ROCKYOU_URL = "https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt"

GREEN, YELLOW, CYAN, DIM, BOLD, RED, RESET = (
    "\033[32m", "\033[33m", "\033[36m", "\033[2m", "\033[1m", "\033[31m", "\033[0m"
)


def _c(code: str, text: str, color: bool) -> str:
    return f"{code}{text}{RESET}" if color else text


def _section_header(sid: str, color: bool) -> str:
    meta = SECTIONS[sid]
    return _c(BOLD, f"=== {meta['titulo'].upper()} ===", color)


def describe_section(sid: str, color: bool) -> None:
    meta = SECTIONS[sid]
    print(_section_header(sid, color))
    print(meta["descripcion"])
    print(_c(GREEN, "\nQué puede hacer:", color))
    for item in meta["puede"]:
        print("  • " + item)
    print(_c(RED, "\nQué NO puede hacer:", color))
    for item in meta["no_puede"]:
        print("  • " + item)


def _print_cifrado(report, color: bool, verbose: bool) -> None:
    print(_section_header("cifrado", color))
    best = report.best
    if len(best.chain) == 1:
        print(_c(BOLD, "Cifrado detectado: ", color) + _c(CYAN, best.chain[0], color))
    else:
        print(_c(BOLD, f"Cifrado detectado ({len(best.chain)} capas, en orden de descifrado):", color))
        for i, step in enumerate(best.chain, 1):
            print(f"  {i}. " + _c(CYAN, step, color))
    print(_c(BOLD, "Texto descifrado:", color))
    print(_c(GREEN, best.text, color))
    if verbose and len(report.candidates) > 1:
        print(_c(DIM, "\nOtros candidatos:", color))
        for n in report.candidates:
            if n is best:
                continue
            preview = n.text.replace("\n", " ")[:80]
            print(_c(DIM, f"  [{n.score:.2f}] {' -> '.join(n.chain)}: {preview}", color))


def _aviso_diccionario(info, color: bool, wordlist: str, hash_text: str) -> None:
    """Si el comando usa un diccionario y no existe en el equipo, dice cómo bajarlo."""
    if "diccionario" not in info["commands"]:
        return  # esta herramienta no usa wordlist (p. ej. solo identificar)
    if os.path.isfile(os.path.expanduser(wordlist)):
        return  # ya lo tiene
    print(_c(YELLOW, f"\n  Aún no tienes el diccionario en {wordlist}", color))
    print(_c(DIM, "  Descárgalo (rockyou, ~130 MB):", color))
    print("     " + _c(GREEN, f"curl -L -o ~/rockyou.txt {ROCKYOU_URL}", color))
    if "rockyou" in wordlist:
        print(_c(DIM, "  (en Kali/Parrot suele venir ya: "
                      "sudo apt install wordlists && sudo gunzip -k /usr/share/wordlists/rockyou.txt.gz)", color))
    print(_c(DIM, "  Y vuelve a lanzar apuntando a ese archivo con -w:", color))
    print("     " + _c(GREEN, f"cryptohunter -w ~/rockyou.txt '{hash_text}'", color))


def _print_hash(match, color: bool, tool: str, wordlist: str, verbose: bool) -> None:
    print(_section_header("hash", color))
    print("Esto parece un HASH. Un hash no se puede descifrar; solo se puede intentar")
    print("adivinar la contraseña original con otra herramienta (por diccionario).")

    top = match.candidates[0]
    nota = f"  ({top.note})" if top.note else ""
    print(_c(BOLD, "\n  Tipo más probable: ", color) + _c(CYAN, top.name, color) + _c(DIM, nota, color))
    if len(match.candidates) > 1:
        otros = ", ".join(c.name for c in match.candidates[1:])
        print(_c(DIM, "  Otros posibles:    " + otros, color))

    info = commands_for(match, tool=tool, candidate_index=0, wordlist=wordlist)
    print(_c(BOLD, f"\nPara intentar romperlo con «{tool}»:", color))
    if "error" in info:
        print(_c(RED, "  " + info["error"], color))
        return
    if info.get("unsupported"):
        print(_c(DIM, "  " + info["unsupported"], color))
    else:
        primero = info["commands"].get("diccionario") or next(iter(info["commands"].values()))
        print(_c(DIM, "  1) guarda el hash en un archivo:", color))
        print("     " + _c(GREEN, f"echo '{match.text}' > hash.txt", color))
        print(_c(DIM, "  2) lánzalo:", color))
        print("     " + _c(GREEN, primero, color))
        _aviso_diccionario(info, color, wordlist, match.text)

    print(_c(DIM, "\nConsejos:", color))
    if not verbose:
        print(_c(DIM, "  • Ver todos los tipos y comandos: añade  -v", color))
    print(_c(DIM, "  • Usar otra herramienta:          -t john   /   -t hashid", color))
    print(_c(DIM, "  • Cambiar el diccionario:         -w /ruta/a/tu/wordlist.txt", color))

    if not verbose:
        return
    print(_c(BOLD, f"\nTodos los comandos con «{tool}»:", color))
    for i, c in enumerate(match.candidates):
        info = commands_for(match, tool=tool, candidate_index=i, wordlist=wordlist)
        label = _c(CYAN, c.name, color)
        if info.get("unsupported"):
            print(f"  {label}: " + _c(DIM, info["unsupported"], color))
            continue
        for kind, cmd in info["commands"].items():
            print(f"  {label} [{kind}]:")
            print("    " + _c(GREEN, cmd, color))
    print(_c(DIM, f"\nMás info: {info.get('url', '')}", color))


def _print_identificacion(info, color: bool) -> None:
    print(_section_header("identificacion", color))
    print(_c(BOLD, "Formato: ", color) + _c(CYAN, info.name, color))
    print("  " + info.note)


def print_result(res, color: bool, verbose: bool, tool: str, wordlist: str) -> None:
    if not res.sections_present:
        print(_c(YELLOW, "No se detectó ningún cifrado, hash ni formato conocido.", color))
        return
    blocks = []
    if "cifrado" in res.sections_present:
        blocks.append(lambda: _print_cifrado(res.cipher, color, verbose))
    if "hash" in res.sections_present:
        blocks.append(lambda: _print_hash(res.hash_match, color, tool, wordlist, verbose))
    if "identificacion" in res.sections_present:
        blocks.append(lambda: _print_identificacion(res.format_info, color))
    for i, block in enumerate(blocks):
        if i:
            print()
        block()


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="cryptohunter",
        description="Detecta automáticamente cifrados (y los descifra) o hashes (y da el comando para romperlos).",
    )
    p.add_argument("texto", nargs="?", help="texto a analizar (si se omite se lee de stdin)")
    p.add_argument("-f", "--file", help="leer el texto desde un archivo")
    p.add_argument("-d", "--depth", type=int, default=6, help="capas máximas de decodificación (6)")
    p.add_argument("-v", "--verbose", action="store_true", help="mostrar otros candidatos")
    p.add_argument("-t", "--tool", default="hashcat",
                   help="herramienta para los comandos de hash: hashcat (def.), john, name-that-hash, hashid")
    p.add_argument("-w", "--wordlist", default="/usr/share/wordlists/rockyou.txt",
                   help="ruta del diccionario en los comandos de hash")
    p.add_argument("--section", choices=list(SECTIONS),
                   help="mostrar la descripción de una sección y salir")
    p.add_argument("--json", action="store_true", help="salida en JSON")
    p.add_argument("--no-color", action="store_true", help="desactivar colores")
    p.add_argument("--web", action="store_true", help="abrir la interfaz web local")
    p.add_argument("--port", type=int, default=8000, help="puerto de la interfaz web (8000)")
    p.add_argument("--list", action="store_true", help="listar los cifrados soportados")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    p = build_parser()
    args = p.parse_args(argv)
    color = not args.no_color and sys.stdout.isatty()

    if args.list:
        for d in DECODERS:
            print(f"[{d.category:11}] {d.name}")
        return 0

    if args.section and args.texto is None and not args.file:
        describe_section(args.section, color)
        return 0

    if args.web:
        from .web import serve

        serve(args.port)
        return 0

    if args.file:
        with open(args.file, encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    elif args.texto is not None:
        text = args.texto
    elif not sys.stdin.isatty():
        text = sys.stdin.read()
    else:
        p.print_help()
        return 1

    res = scan(text, max_depth=args.depth)
    if args.json:
        print(json.dumps(result_to_dict(res), ensure_ascii=False, indent=2))
    else:
        print_result(res, color=color, verbose=args.verbose, tool=args.tool, wordlist=args.wordlist)
    return 0 if res.sections_present else 2


if __name__ == "__main__":
    raise SystemExit(main())
