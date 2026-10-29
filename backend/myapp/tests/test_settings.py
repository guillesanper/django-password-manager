"""L1 — aserciones sobre la configuración de PRODUCCIÓN.

Cubre A8-a, C6 (LEEWAY≤30), M6 y BL1.

REGLA DURA (§6): estos tests importan `demo.settings` EXPLÍCITAMENTE, nunca
`django.conf.settings` —que ya viene tocado por settings_test (DEBUG, Redis db 15,
bucket, logging)—. Si M6 leyera django.conf.settings comprobaría el override del test
y daría verde con IGNORE_EXCEPTIONS intacto en producción: falso verde en el hallazgo
que dice que la seguridad falla en abierto.

Matiz importante sobre `demo.settings.CACHES`: settings_test hace
`from demo.settings import *` y muta EN SITIO el `LOCATION`/`KEY_PREFIX` de cada caché
(reapunta a la db 15). Ese dict es el mismo objeto que `demo.settings.CACHES`, así que
su `LOCATION` ya NO refleja producción. Por eso:
  - M6 lee sólo `OPTIONS['IGNORE_EXCEPTIONS']`, que settings_test NO toca → fiable.
  - BL1 NO lee `CACHES[...]['LOCATION']` (contaminado): usa el nombre de módulo
    `REDIS_URL` (intacto) para `default` y la variable de entorno propia de `sessions`,
    que es como producción decide ambas.
"""

import os

import pytest

import demo.settings as prod

pytestmark = pytest.mark.l1


def _redis_db(url: str) -> str:
    """Número de base de datos al final de una URL redis://…/<n> (o '' si no hay)."""
    tail = url.rstrip("/").rsplit("/", 1)
    return tail[-1] if len(tail) == 2 and tail[-1].isdigit() else ""


# --------------------------------------------------------------------------- #
# A8-a — el primer hasher es Argon2
# --------------------------------------------------------------------------- #
def test_a8a_password_hashers_argon2_primero():
    assert prod.PASSWORD_HASHERS[0] == (
        "django.contrib.auth.hashers.Argon2PasswordHasher"
    ), (
        "El PRIMER hasher debe ser Argon2: es con el que se guardan las contraseñas "
        "nuevas y el que iguala el coste del señuelo de A6."
    )


# --------------------------------------------------------------------------- #
# C6 — LEEWAY acotado (<= 30 s)
# --------------------------------------------------------------------------- #
def test_c6_leeway_acotado():
    leeway = prod.SIMPLE_JWT["LEEWAY"]
    assert leeway <= 30, (
        f"LEEWAY={leeway}: por encima de 30 s regala validez EXTRA a un token ya "
        "expirado (C6). Estaba en 300 (5 min)."
    )


# --------------------------------------------------------------------------- #
# M6 — la caché falla CERRADA (IGNORE_EXCEPTIONS is False)
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("cache_name", ["default", "sessions"])
def test_m6_cache_ignore_exceptions_false(cache_name):
    # `is False` estricto: un valor "falsy" (None, 0) NO cuenta como fail-closed.
    assert prod.CACHES[cache_name]["OPTIONS"]["IGNORE_EXCEPTIONS"] is False, (
        f"CACHES['{cache_name}'] debe fallar CERRADA (M6): con IGNORE_EXCEPTIONS "
        "verdadero, un Redis caído apaga en silencio rate limiting y bloqueos."
    )


# --------------------------------------------------------------------------- #
# BL1 — default y sessions a bases Redis distintas, desde variables distintas
# --------------------------------------------------------------------------- #
def test_bl1_redis_default_y_sessions_a_db_distintas():
    # `default` toma REDIS_URL (nombre de módulo, intacto por settings_test).
    default_url = prod.REDIS_URL
    # `sessions` toma su PROPIA variable REDIS_SESSIONS_URL: ya no cae en REDIS_URL.
    # Se lee como lo hace producción (mismo default que en demo/settings.py).
    sessions_url = os.getenv("REDIS_SESSIONS_URL", "redis://redis:6379/2")

    assert default_url != sessions_url, (
        "default y sessions deben leerse de URLs distintas (la de sesiones ya no "
        f"cae en REDIS_URL): default={default_url!r}, sessions={sessions_url!r}"
    )

    db_default = _redis_db(default_url)
    db_sessions = _redis_db(sessions_url)
    assert db_default and db_sessions, (
        f"Ambas URLs deben fijar una db explícita: {default_url!r} / {sessions_url!r}"
    )
    assert db_default != db_sessions, (
        f"default y sessions deben ir a bases Redis distintas (BL1): "
        f"db {db_default} vs db {db_sessions}."
    )
