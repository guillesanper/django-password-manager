"""L1 — batería G de validadores de contraseña.

Cubre G6 (§5): `CustomPasswordValidator` (myapp/validators.py) y la cadena completa
`AUTH_PASSWORD_VALIDATORS` aceptan/rechazan lo esperado, INCLUIDO el caso con `;`
(cruce con M12): una contraseña que contiene `;` pero cumple el resto de reglas debe
ser ACEPTADA. El detector M12 no mira el cuerpo; el validador tampoco penaliza `;`
(está en su clase de símbolos válidos), así que las dos capas coinciden.

REGLA DURA (§6): la cadena se lee de `demo.settings.AUTH_PASSWORD_VALIDATORS`
EXPLÍCITAMENTE (vía get_password_validators), nunca de `django.conf.settings`. Aunque
settings_test no toca esta clave, se respeta la regla por coherencia con el resto.

No es xfail: debe pasar hoy (§3). No necesita BD (los validadores no consultan el ORM;
CommonPasswordValidator sólo lee su fichero de palabras).
"""

import pytest
from django.contrib.auth.password_validation import (
    get_password_validators,
    validate_password,
)
from django.core.exceptions import ValidationError

import demo.settings as prod
from myapp.tests.conftest import TEST_ACCOUNT_PASSWORD, TEST_MASTER_PASSWORD
from myapp.validators import CustomPasswordValidator

pytestmark = pytest.mark.l1

# Cadena real de producción, construida a partir de demo.settings (regla dura §6).
_CHAIN = get_password_validators(prod.AUTH_PASSWORD_VALIDATORS)

# Una contraseña con `;` que cumple TODO lo demás: mayús+minús+dígito+símbolo, >=12,
# sin secuencias/palabras/fechas/repeticiones. `;` es símbolo válido del validador.
PWD_CON_PUNTO_Y_COMA = "Wren;Kilo7pluto"

# Contraseñas buenas para el camino feliz (las de fixture cumplen las 3 restricciones).
PWD_BUENAS = [TEST_MASTER_PASSWORD, TEST_ACCOUNT_PASSWORD, PWD_CON_PUNTO_Y_COMA]


# =========================================================================== #
# CustomPasswordValidator aislado
# =========================================================================== #
def _custom_rechaza(password) -> str:
    """Devuelve el/los code(s) de error de CustomPasswordValidator, o '' si acepta."""
    try:
        CustomPasswordValidator().validate(password)
        return ""
    except ValidationError as exc:
        return ",".join(getattr(e, "code", "") for e in exc.error_list)


def test_g6_custom_acepta_contrasenas_validas():
    for pwd in PWD_BUENAS:
        code = _custom_rechaza(pwd)
        assert code == "", f"CustomPasswordValidator rechazó {pwd!r} con code={code!r}."


@pytest.mark.parametrize(
    "password, code_esperado",
    [
        ("Wr$7a",            "password_too_short"),       # < 12
        ("wren$kilo7pluto",  "password_no_upper"),        # sin mayúscula
        ("WREN$KILO7PLUTO",  "password_no_lower"),        # sin minúscula
        ("Wren$Kilopluto",   "password_no_number"),       # sin dígito
        ("WrenKilo7pluto",   "password_no_symbol"),       # sin símbolo
        ("Wren$Kaaa7pluto",  "password_too_many_consecutive"),  # 'aaa'
        ("Wren$Password7x",  "password_common_word"),     # contiene 'password'
        ("Wren$K2020pluto",  "password_contains_date"),   # año 2020
        ("Wren$abcdef7Zx",   "password_common_sequence"), # 'abcdef'
    ],
)
def test_g6_custom_rechaza_lo_esperado(password, code_esperado):
    codes = _custom_rechaza(password)
    assert code_esperado in codes, (
        f"Se esperaba que {password!r} fuese rechazada por {code_esperado!r}; "
        f"codes={codes!r}."
    )


# =========================================================================== #
# Cadena completa AUTH_PASSWORD_VALIDATORS (validate_password)
# =========================================================================== #
def _chain_ok(password) -> bool:
    try:
        validate_password(password, password_validators=_CHAIN)
        return True
    except ValidationError:
        return False


def test_g6_cadena_acepta_contrasenas_validas():
    for pwd in PWD_BUENAS:
        assert _chain_ok(pwd), f"La cadena AUTH_PASSWORD_VALIDATORS rechazó {pwd!r}."


@pytest.mark.parametrize(
    "password",
    [
        "corto",              # < 12 (MinimumLengthValidator)
        "aaaaaaaaaaaa",       # 12 iguales: sin mayús/número/símbolo + repetición
        "123456789012",       # sólo dígitos (NumericPasswordValidator + Custom)
        "Password1234!!",     # palabra común 'password' + secuencia '1234'
    ],
)
def test_g6_cadena_rechaza_lo_esperado(password):
    assert not _chain_ok(password), (
        f"La cadena AUTH_PASSWORD_VALIDATORS debió rechazar {password!r}."
    )


# =========================================================================== #
# Cruce con M12 — el `;` no es motivo de rechazo en ninguna de las dos capas
# =========================================================================== #
def test_g6_punto_y_coma_aceptado_en_ambas_capas():
    # CustomPasswordValidator: `;` está en su clase de símbolos válidos.
    assert _custom_rechaza(PWD_CON_PUNTO_Y_COMA) == "", (
        "Una contraseña con `;` que cumple el resto de reglas NO debe rechazarse "
        "(cruce con M12: la seguridad no bloquea por subcadenas)."
    )
    # Cadena completa: idéntico veredicto.
    assert _chain_ok(PWD_CON_PUNTO_Y_COMA), (
        "La cadena completa debe aceptar la contraseña con `;`."
    )
