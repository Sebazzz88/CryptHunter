import pytest

from cryptohunter import formats
from cryptohunter.hashes import TOOLS, commands_for, identify
from cryptohunter.scan import SECTIONS, result_to_dict, scan

HASHES = {
    "5d41402abc4b2a76b9719d911017c592": "MD5",
    "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d": "SHA-1",
    "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824": "SHA-256",
    "$2y$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy": "bcrypt",
    "$6$rounds=5000$usesomesillystri$D4IrlXatmP7rx3P3InaxBeoomnAihCKRVQP22JZ6EY47Wc6BkroIuUUBOov1i.S5KPgErtP/EN5mcO.ChWQW1": "SHA-512-crypt (Unix)",
}


@pytest.mark.parametrize("h,name", HASHES.items())
def test_identifica_tipo(h, name):
    m = identify(h)
    assert m is not None, h
    assert any(c.name == name for c in m.candidates), [c.name for c in m.candidates]


def test_texto_normal_no_es_hash():
    assert identify("hola mundo esto no es un hash") is None
    assert identify("este es un mensaje secreto muy importante") is None


def test_comandos_hashcat_y_john():
    m = identify("5d41402abc4b2a76b9719d911017c592")
    hc = commands_for(m, tool="hashcat", candidate_index=0)
    assert hc["commands"]["diccionario"].startswith("hashcat -m 0 -a 0")
    jr = commands_for(m, tool="john", candidate_index=0)
    assert "--format=raw-md5" in jr["commands"]["diccionario"]


def test_wordlist_personalizada():
    m = identify("5d41402abc4b2a76b9719d911017c592")
    out = commands_for(m, tool="hashcat", wordlist="/ruta/mi.txt")
    assert "/ruta/mi.txt" in out["commands"]["diccionario"]


def test_todas_las_herramientas_responden():
    m = identify("5d41402abc4b2a76b9719d911017c592")
    for tool in TOOLS:
        out = commands_for(m, tool=tool)
        assert "error" not in out
        assert out["commands"] or out.get("unsupported")


def test_formatos():
    assert formats.identify("ssh-rsa AAAAB3NzaC1yc2E").name == "Clave pública SSH"
    assert formats.identify("550e8400-e29b-41d4-a716-446655440000").name == "UUID"
    assert formats.identify("texto cualquiera") is None


def test_scan_elige_seccion():
    assert scan("5d41402abc4b2a76b9719d911017c592").sections_present == ["hash"]
    assert "cifrado" in scan("Krod pxqgr, hvwh hv xq phqvdmh vhfuhwr").sections_present
    assert scan("ssh-ed25519 AAAAC3Nza").sections_present == ["identificacion"]
    assert scan("xyzzy plugh +++ ???").sections_present == []


def test_result_to_dict_serializable():
    import json

    d = result_to_dict(scan("5d41402abc4b2a76b9719d911017c592"))
    json.dumps(d)  # no debe lanzar
    assert "hash" in d["sections"]


def test_hay_tres_secciones_descritas():
    for sid in ("cifrado", "hash", "identificacion"):
        meta = SECTIONS[sid]
        assert meta["titulo"] and meta["descripcion"] and meta["puede"] and meta["no_puede"]
