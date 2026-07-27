"""L1 — batería G del generador de contraseñas.

Cubre G5 (§5): `generate_passwords` respeta longitud/cantidad/alfabeto (símbolos y
mayúsculas según sus flags; los dígitos van SIEMPRE) y sigue usando `secrets`
(CSPRNG), nunca el módulo `random`.

Firma REAL verificada en myapp/encryption_utils.py:

    generate_passwords(ammount, length, symbols, uppercase) -> list[str]

    alfabeto = ascii_lowercase + digits           (base, siempre)
             + punctuation      si symbols
             + ascii_uppercase  si uppercase

No es xfail: con la purga cripto de la Fase 2 (paso 27) el único superviviente del
módulo es este generador y debe pasar hoy (§3).
"""

import inspect
import re
import string

import pytest

from myapp import encryption_utils
from myapp.encryption_utils import generate_passwords

pytestmark = pytest.mark.l1

_BASE = set(string.ascii_lowercase) | set(string.digits)
_PUNCT = set(string.punctuation)
_UPPER = set(string.ascii_uppercase)


# --------------------------------------------------------------------------- #
# G5 — cantidad y longitud exactas
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("ammount", [0, 1, 5, 20])
@pytest.mark.parametrize("length", [1, 8, 32, 64])
def test_g5_cantidad_y_longitud_respetadas(ammount, length):
    passwords = generate_passwords(ammount, length, symbols=True, uppercase=True)

    assert isinstance(passwords, list)
    assert len(passwords) == ammount, (
        f"Se pidieron {ammount} contraseñas y se devolvieron {len(passwords)}."
    )
    for pwd in passwords:
        assert isinstance(pwd, str)
        assert len(pwd) == length, (
            f"Longitud pedida {length}, obtenida {len(pwd)} en {pwd!r}."
        )


# --------------------------------------------------------------------------- #
# G5 — alfabeto: los flags SÓLO añaden, nunca quitan la base (lower+dígitos)
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "symbols, uppercase, permitido",
    [
        (False, False, _BASE),
        (True, False, _BASE | _PUNCT),
        (False, True, _BASE | _UPPER),
        (True, True, _BASE | _PUNCT | _UPPER),
    ],
)
def test_g5_alfabeto_respeta_los_flags(symbols, uppercase, permitido):
    # Muestra amplia: 40 contraseñas de 60 chars = 2400 caracteres. Basta para que
    # NINGÚN carácter fuera del alfabeto permitido se cuele si el flag está apagado.
    usados = set()
    for pwd in generate_passwords(40, 60, symbols, uppercase):
        usados |= set(pwd)

    prohibido = usados - permitido
    assert not prohibido, (
        f"Con symbols={symbols}, uppercase={uppercase} aparecieron caracteres fuera "
        f"del alfabeto permitido: {sorted(prohibido)!r}"
    )

    # Y cuando el flag está APAGADO, su clase no debe aparecer en absoluto.
    if not symbols:
        assert not (usados & _PUNCT), "Con symbols=False no debe haber puntuación."
    if not uppercase:
        assert not (usados & _UPPER), "Con uppercase=False no debe haber mayúsculas."


# --------------------------------------------------------------------------- #
# G5 — presencia estadística de cada clase habilitada (2400 chars ≈ certeza)
# --------------------------------------------------------------------------- #
def test_g5_clases_habilitadas_aparecen():
    usados = set()
    for pwd in generate_passwords(40, 60, symbols=True, uppercase=True):
        usados |= set(pwd)

    # Los dígitos van SIEMPRE en el alfabeto base (la firma no tiene flag de números).
    assert usados & set(string.digits), "Los dígitos deben estar en el alfabeto base."
    assert usados & _UPPER, "Con uppercase=True deben aparecer mayúsculas."
    assert usados & _PUNCT, "Con symbols=True deben aparecer símbolos."
    # La base minúscula también.
    assert usados & set(string.ascii_lowercase), "Deben aparecer minúsculas."


# --------------------------------------------------------------------------- #
# G5 — sigue usando `secrets` (CSPRNG), no el `random` sesgado/predecible
# --------------------------------------------------------------------------- #
def test_g5_usa_secrets_no_random():
    modulo_src = inspect.getsource(encryption_utils)
    func_src = inspect.getsource(generate_passwords)

    # El generador extrae índices con secrets.randbelow (rechazo insesgado del CSPRNG).
    assert "secrets.randbelow" in func_src, (
        "generate_passwords debe elegir cada carácter con secrets.randbelow (CSPRNG)."
    )
    assert re.search(r"^\s*import secrets\b", modulo_src, re.M), (
        "encryption_utils debe importar el módulo `secrets`."
    )

    # Ni el módulo `random` (Mersenne Twister, predecible) ni ninguno de sus métodos.
    assert not re.search(r"^\s*import random\b", modulo_src, re.M), (
        "encryption_utils no debe importar el módulo `random` (predecible)."
    )
    assert not re.search(r"\brandom\.(choice|randint|randrange|random|sample|shuffle)\b",
                         modulo_src), (
        "No debe usarse el PRNG `random.*`: el generador es CSPRNG (secrets)."
    )
