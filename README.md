# CryptoHunter 🔍

**Script de terminal que detecta automáticamente en qué cifrado o codificación está un texto y lo descifra.**
Como la función *Magic* de CyberChef, pero sin tener que elegir nada: le pasas el texto y la herramienta
prueba todo por su cuenta, incluso cuando hay varias capas encadenadas (por ejemplo `Base64 → Hex → ROT13`).

Está organizada en tres apartados; cada uno dice qué puede y qué no puede hacer (`--section <nombre>`):

- **cifrado** → detecta y **descifra** solo (codificaciones y cifrados clásicos).
- **hash** → solo **detecta el tipo** de hash (no se puede descifrar) y te da el comando para intentar
  romperlo con la herramienta que prefieras (hashcat, John the Ripper, Name-That-Hash, hashid).
- **identificacion** → reconoce formatos que no se abren aquí (PEM, SSH, UUID, PGP, OpenSSL `Salted__`).

```
$ cryptohunter "Krod pxqgr, hvwh hv xq phqvdmh vhfuhwr"
=== CIFRADO Y CODIFICACIÓN ===
Cifrado detectado: César (clave 3)
Texto descifrado:
Hola mundo, este es un mensaje secreto

$ cryptohunter "NzI2NjY3NzIyMDcyNjYyMDY4NjEyMDdhNzI2MTY2NmU3NzcyMjA2NjcyNzA2NTcyNjc2Mg=="
=== CIFRADO Y CODIFICACIÓN ===
Cifrado detectado (3 capas, en orden de descifrado):
  1. Base64
  2. Hex
  3. ROT13
Texto descifrado:
este es un mensaje secreto

$ cryptohunter "5d41402abc4b2a76b9719d911017c592"
=== HASHES ===
...
Tipo(s) de hash probable(s):
  0. MD5
  ...
  MD5 [diccionario]:
    hashcat -m 0 -a 0 hash.txt /usr/share/wordlists/rockyou.txt
```

- ✅ 100 % automático: no hay que elegir el tipo de cifrado
- ✅ Resuelve cadenas de varias capas (hasta 6 por defecto)
- ✅ Rompe cifrados con clave sin conocerla (César, Vigenère, Afín, XOR...)
- ✅ Detecta el tipo de hash y arma el comando para la herramienta que elijas
- ✅ Entiende texto en **español** e **inglés**
- ✅ Sin dependencias: solo la librería estándar de Python (3.10+)

## Instalación

```bash
git clone https://github.com/Sebazzz88/CryptHunter.git
cd CryptHunter
pip install -e .
```

También funciona sin instalar: `python3 -m cryptohunter "texto"`.

## Uso

```bash
cryptohunter "uryyb jbeyq"                 # texto como argumento
echo "SGVsbG8gV29ybGQ=" | cryptohunter     # desde stdin
cryptohunter -f mensaje.txt                # desde un archivo
cryptohunter -v "texto"                    # mostrar otros candidatos
cryptohunter --json "texto"                # salida JSON (para scripts)
cryptohunter --section hash                # ver qué hace el apartado de hashes
cryptohunter --list                        # listar todo lo soportado
```

El código de salida es `0` si se detectó algo y `2` si no.

### Hashes

Un hash no se puede descifrar. Con un hash, la herramienta detecta el tipo y te da el comando listo:

```bash
cryptohunter "5d41402abc4b2a76b9719d911017c592"              # comandos para hashcat (por defecto)
cryptohunter -t john "5d41402abc4b2a76b9719d911017c592"      # comandos para John the Ripper
cryptohunter -t hashid "5d41402abc4b2a76b9719d911017c592"    # solo identificar con hashid
cryptohunter -w ~/mi_wordlist.txt "5d414..."                 # usar tu propio diccionario
```

Herramientas soportadas en `-t/--tool`: `hashcat`, `john`, `name-that-hash`, `hashid`. La herramienta solo
te **muestra** el comando; el ataque lo ejecutas tú en tu equipo.

### Interfaz web (extra opcional)

Además del script, `cryptohunter --web` abre una página local (solo en `127.0.0.1`) con los mismos apartados
en pestañas. Es un extra; el uso principal es por terminal.

## Qué hace cada parte

La herramienta decide sola en cuál de estos tres apartados cae el texto que le pasas
(no tienes que elegirlo). Puedes leer la explicación de cada uno con `cryptohunter --section <nombre>`.

| Apartado | Qué hace | Qué NO hace |
|----------|----------|-------------|
| **cifrado** | Detecta la codificación/cifrado y **lo descifra** solo, incluso varias capas encadenadas (p. ej. `Base64 → Hex → ROT13`). | No rompe cifrado moderno con clave (AES, RSA...). |
| **hash** | **Solo detecta el tipo** de hash y te da el comando listo para intentar romperlo con la herramienta que elijas. | No descifra el hash (es imposible) ni ejecuta el ataque por ti. |
| **identificacion** | Reconoce formatos que no se abren aquí y te dice qué son. | No descifra claves ni certificados. |

## Cifrados y codificaciones que detecta (apartado «cifrado»)

Estos sí se **descifran** automáticamente:

| Grupo | Lista |
|-------|-------|
| **Codificaciones** | Base64, Base64 URL-safe, Base32, Base16/Hex, Base58, Base62, Base85 / Ascii85 / Z85, Base45, Binario (7 y 8 bits), Octal, Decimal ASCII, Entero grande → bytes, URL encoding, Entidades HTML, Escapes Unicode / `\x`, Quoted-Printable, UUencode, JWT |
| **Cifrados clásicos** | ROT13, César (prueba las 26 rotaciones), ROT47, ROT5 / ROT18, Atbash, Afín (fuerza bruta), Vigenère (sin clave: índice de coincidencia + análisis de frecuencias), Rail Fence, Escítala / transposición por columnas, Texto invertido |
| **XOR** | XOR de un byte (fuerza bruta), XOR con clave repetida (distancia de Hamming) |
| **Alfabetos y códigos** | Morse, Bacon, A1Z26, Polybius, Tap code, Teclado de móvil (multi-tap) |
| **Compresión** | Gzip, Zlib / Deflate, Bzip2, LZMA / XZ |
| **Esotéricos** | Brainfuck, Ook! |

## Tipos de hash que detecta (apartado «hash»)

Estos **no se descifran**: solo se identifica el tipo y se da el comando para intentar
recuperarlos con una herramienta externa (`hashcat`, `john`, `name-that-hash` o `hashid`).

| Grupo | Lista |
|-------|-------|
| **Comunes** | MD5, MD4, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512 |
| **SHA-3 / otros** | SHA3-224, SHA3-256, SHA3-384, SHA3-512, RIPEMD-160, Whirlpool, BLAKE2s-256, BLAKE2b-512, Keccak-512 |
| **Windows** | NTLM, LM, NTLM con salt |
| **Con contraseña (lentos)** | bcrypt, Argon2, MD5-crypt / SHA-256-crypt / SHA-512-crypt (Unix), yescrypt, phpass (WordPress/phpBB) |
| **Apps / frameworks** | Django (PBKDF2-SHA256), PBKDF2-HMAC-SHA256, MySQL 3.x y 4.1+, Oracle 11g, LDAP `{SHA}` / `{SSHA}`, vBulletin |
| **Con salt (MD5)** | `md5($pass.$salt)`, `md5($salt.$pass)`, `md5(md5($pass).$salt)`, doble MD5 |
| **Checksums** | CRC32, Adler-32 (no son criptográficos) |

> Cuando un hash encaja con varias longitudes iguales (p. ej. 32 hex = MD5, MD4, NTLM...),
> se muestran todos los candidatos ordenados del más probable al menos probable.

## Formatos que identifica (apartado «identificacion»)

No son texto cifrado que esta herramienta abra; solo te dice qué son:
bloques **PEM**, claves públicas **SSH**, mensajes **PGP/GPG**, **OpenSSL `Salted__`** y **UUID**.

> Los hashes son funciones de un solo sentido: no se pueden "descifrar". La herramienta te dice qué tipo de
> hash parece ser y el comando para intentar romperlo por diccionario/fuerza bruta con una herramienta
> externa. Tampoco se pueden romper cifrados modernos como AES o RSA sin la clave.

## Cómo funciona

1. **Decodificadores**: cada uno comprueba rápido si la entrada encaja con su formato (alfabeto, longitud,
   cabeceras mágicas...) y, si encaja, devuelve el resultado. Los cifrados con clave prueban todas las claves
   posibles o la deducen con análisis estadístico.
2. **Puntuación**: cada resultado recibe una nota según cuánto se parece a texto real: palabras comunes en
   español/inglés, frecuencia de letras, espacios y caracteres imprimibles.
3. **Búsqueda en haz**: se aplican todos los decodificadores, se quedan los mejores resultados y se vuelve a
   decodificar sobre ellos, capa a capa. Gana la cadena con mejor puntuación; las cadenas más cortas y las
   codificaciones estrictas se prefieren frente a la fuerza bruta.

```
cryptohunter/
├── engine.py        # búsqueda automática por capas (descifrado)
├── scoring.py       # "¿esto parece texto legible?"
├── scan.py          # escáner por secciones (cifrado / hash / identificación)
├── hashes.py        # tipos de hash + comandos para hashcat/john/...
├── formats.py       # formatos que no se descifran (PEM, SSH, UUID...)
├── registry.py      # registro de decodificadores
├── cli.py           # script de terminal (interfaz principal)
├── web.py           # interfaz web local (extra opcional)
└── decoders/
    ├── encodings.py # Base64, Hex, URL...
    ├── classical.py # César, Vigenère, Morse...
    └── modern.py    # XOR, compresión, JWT, Brainfuck
```

### Añadir un decodificador

```python
from cryptohunter.registry import as_text, decoder

@decoder("Mi cifrado", "cipher")
def mi_cifrado(data: bytes):
    text = as_text(data)
    if not text or not parece_mi_formato(text):
        return []
    return [("Mi cifrado", descifrar(text).encode())]
```

Ponlo en uno de los módulos de `cryptohunter/decoders/` y el motor lo usará automáticamente.

## Tests

```bash
pip install -e ".[dev]"
pytest
```

## Licencia

MIT
