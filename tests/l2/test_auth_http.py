"""L2 · stack_dev · Autenticación y superficie de seguridad por HTTP real.

  - C3    `/api/security/analysis/` y `/api/security/check-breach/` (v1, descifraban
          en servidor) YA NO EXISTEN -> 404. Las que quedan responden autenticadas:
          `/api/security/hibp-range/<prefix>/` (proxy k-anonimato) y
          `/api/security/recommendations/`.
  - T3    Cliente nuevo SIN token: `GET /api/csrf/` -> 200 + cookie `csrftoken`
          (antes 401: era el punto muerto del arranque, trampa 8).
  - N1    `POST /api/token/refresh/` con el refresh en la cookie -> 200 + cookies
          reescritas (`CookieTokenRefreshView`).
  - A1-b  La respuesta de login trae `Set-Cookie` HttpOnly + SameSite y el cuerpo
          JSON NO contiene `access`/`refresh`.
  - A5    Tras el logout, reusar ese mismo refresh en `CookieTokenRefreshView` -> 401.
  - Z7    La contraseña maestra NUNCA viaja: setup/verify/params sólo manejan
          material derivado (auth_key), y la maestra en claro no vale como prueba.

Divergencia declarada: la tabla §4.3 sitúa A1-b en `stack_prod`, pero el mapa de
andamiaje del §7 lo pone en este fichero (`stack_dev`). Se sigue el §7, como hizo la
tanda 9 con M4. HttpOnly / SameSite / "sin tokens en el cuerpo" son agnósticos de
pila, así que la propiedad se ejerce igual. **En `stack_dev` NO se afirma `Secure`**:
el override fuerza `DJANGO_TLS_ENABLED=false` y ahí la cookie `Secure` no se fijaría
(se entra por http://localhost:8000 sin nginx). El flag `Secure` es cosa de
`stack_prod` (trampa 12).

Presupuesto de peticiones (trampa 4, §6): el cubo 'auth' de `RateLimitMiddleware`
admite 10 peticiones por IP cada 5 minutos y cuenta TODAS (no sólo los fallos) a
`/auth/login|register|logout/`, `/api/token/` y `/api/master-key/verify/`. Este
bloque gasta 7 (1 login de sesión + 4 del ciclo + 2 verify) y `test_zk_datos` gasta
1 más (el registro de M9). Por eso el ciclo hace UN login y de él cuelgan A1-b, N1 y
A5. **Si se relanza el bloque antes de 5 minutos, el login puede dar 429**: no es un
fallo del código, es el límite haciendo su trabajo; se espera y se repite.
"""

import json
from types import SimpleNamespace

import pytest
import requests

from _l2lib import csrf_headers

pytestmark = [pytest.mark.l2, pytest.mark.stack_dev]


# =========================================================================== #
# C3 — el análisis de seguridad v1 ya no existe; el proxy k-anonimato sí
# =========================================================================== #
_RUTAS_V1_RETIRADAS = [
    "/api/security/analysis/",
    "/api/security/check-breach/",
]


@pytest.mark.parametrize("ruta", _RUTAS_V1_RETIRADAS)
def test_c3_rutas_v1_retiradas_dan_404(auth_session, ruta):
    """Retiradas, no suspendidas en 501: el servidor ya no puede descifrar (paso 27).

    Se pide AUTENTICADO a propósito: así un 404 no puede confundirse con el 401 de
    una ruta viva pero cerrada. Y como el catch-all de la SPA devuelve JSON 404 para
    todo `/api/` desconocido (G3), la respuesta tampoco puede ser 200-HTML.
    """
    session, base_url = auth_session
    r = session.get(base_url + ruta, timeout=20)

    assert r.status_code == 404, (
        f"{ruta} devolvió {r.status_code}; C3 exige que la ruta v1 haya "
        f"desaparecido. Cuerpo: {r.text[:300]}"
    )
    assert "text/html" not in r.headers.get("Content-Type", ""), (
        f"{ruta} devolvió HTML: el catch-all de la SPA se está tragando la API (G3)."
    )


def test_c3_hibp_range_responde_autenticado(auth_session):
    """El proxy k-anonimato existe y responde a una sesión autenticada.

    Se aceptan 200 y 502: el 502 es el camino declarado de `api_hibp_range` cuando
    no puede alcanzar api.pwnedpasswords.com (contenedor sin salida a Internet). En
    ambos casos la ruta está viva y autorizada, que es lo que afirma C3. Lo que NO
    puede salir es 401/403 (autenticado) ni 404 (retirada por error).
    """
    session, base_url = auth_session
    # Prefijo del SHA-1 de una contraseña cualquiera; el servidor sólo ve estos 5 hex.
    r = session.get(base_url + "/api/security/hibp-range/5BAA6/", timeout=30)

    assert r.status_code in (200, 502), (
        f"/api/security/hibp-range/ devolvió {r.status_code}: {r.text[:300]}"
    )
    if r.status_code == 200:
        payload = r.json()
        assert payload.get("success") is True
        assert payload.get("prefix") == "5BAA6"
        assert "ranges" in payload, "el proxy debe devolver los sufijos de HIBP"


def test_c3_hibp_range_valida_el_prefijo(auth_session):
    """Prefijo no hexadecimal -> 400. Prueba la validación sin depender de la red
    (y de paso, que no hay SSRF: el prefijo se acota a 5 hex y el host es fijo)."""
    session, base_url = auth_session
    r = session.get(base_url + "/api/security/hibp-range/zzzzz/", timeout=20)
    assert r.status_code == 400, (
        f"un prefijo inválido devolvió {r.status_code}, se esperaba 400: {r.text[:300]}"
    )


def test_c3_recommendations_responde_autenticado(auth_session):
    """`/api/security/recommendations/` sigue vivo: sólo usa metadatos (fechas y
    conteos), nunca descifra, así que sobrevive al zero-knowledge."""
    session, base_url = auth_session
    r = session.get(base_url + "/api/security/recommendations/", timeout=20)

    assert r.status_code == 200, f"recommendations devolvió {r.status_code}: {r.text[:300]}"
    payload = r.json()
    assert payload.get("success") is True
    assert isinstance(payload.get("recommendations"), list)


# =========================================================================== #
# T3 — el arranque en frío: cookie CSRF sin autenticar
# =========================================================================== #
def test_t3_csrf_sin_token_da_200_y_cookie(http, base_url):
    """Cliente RECIÉN llegado (fixture `http`: sesión nueva, sin cookies ni token).

    Es el primer contacto de la SPA: sin esta cookie no hay login posible, porque
    el login exige CSRF de doble envío. Daba 401 por heredar el `IsAuthenticated`
    de DRF (trampa 8); hoy es `AllowAny` + `authentication_classes([])`.
    """
    r = http.get(base_url + "/api/csrf/", timeout=20)

    assert r.status_code == 200, f"/api/csrf/ devolvió {r.status_code}: {r.text[:300]}"
    assert http.cookies.get("csrftoken"), (
        "no llegó la cookie `csrftoken`: sin ella el cliente nuevo no puede hacer login."
    )
    payload = r.json()
    assert payload.get("success") is True
    assert payload.get("csrfToken"), "el cuerpo debe traer también el token (doble envío)"


# =========================================================================== #
# Ciclo de sesión: un ÚNICO login del que cuelgan A1-b, N1 y A5
# =========================================================================== #
@pytest.fixture(scope="module")
def ciclo_de_sesion(zk_user, base_url):
    """Ejecuta UNA vez la coreografía completa y guarda las respuestas.

        csrf -> login -> refresh (rota) -> logout -> reuso del refresh rotado

    Se graba y luego se afirma, en vez de encadenar tests mutantes: así el
    resultado no depende del orden de ejecución ni de qué tests se seleccionen, y
    el cubo 'auth' se gasta una sola vez (4 peticiones).

    Sesión PROPIA, no la `auth_session` compartida: aquí se hace logout, y matar la
    sesión de los demás tests sería un fallo en cascada.
    """
    s = requests.Session()
    s.verify = False

    r_csrf = s.get(base_url + "/api/csrf/", timeout=20)
    assert r_csrf.status_code == 200, f"/api/csrf/ devolvió {r_csrf.status_code}"

    r_login = s.post(
        base_url + "/auth/login/",
        data=json.dumps({"email": zk_user.email, "password": zk_user.django_password}),
        headers=csrf_headers(s, base_url, {"Content-Type": "application/json"}),
        timeout=30,
    )
    if r_login.status_code == 429:
        pytest.skip(
            "cubo 'auth' agotado (10 peticiones/5 min por IP): el bloque se ha "
            "relanzado demasiado pronto. Espera 5 minutos y repite."
        )
    assert r_login.status_code == 200, f"login falló ({r_login.status_code}): {r_login.text[:400]}"

    access_1 = s.cookies.get("access_token")
    refresh_1 = s.cookies.get("refresh_token")

    # N1: renovación leyendo el refresh de la cookie HttpOnly.
    r_refresh = s.post(
        base_url + "/api/token/refresh/",
        headers=csrf_headers(s, base_url),
        timeout=30,
    )
    access_2 = s.cookies.get("access_token")
    refresh_2 = s.cookies.get("refresh_token")

    # A5: el refresh que acaba de emitir la rotación está VIVO (7 días) hasta que
    # el logout lo invalide. Se guarda antes de cerrar sesión para reusarlo después.
    r_logout = s.post(
        base_url + "/auth/logout/",
        headers=csrf_headers(s, base_url),
        timeout=30,
    )

    r_reuso = s.post(
        base_url + "/api/token/refresh/",
        headers=csrf_headers(s, base_url),
        cookies={"refresh_token": refresh_2 or ""},
        timeout=30,
    )

    yield SimpleNamespace(
        login=r_login,
        refresh=r_refresh,
        logout=r_logout,
        reuso=r_reuso,
        access_1=access_1,
        access_2=access_2,
        refresh_1=refresh_1,
        refresh_2=refresh_2,
    )
    s.close()


def _set_cookies(respuesta):
    """Lista de cabeceras `Set-Cookie` sin fusionar (requests las une con coma)."""
    return list(respuesta.raw.headers.getlist("Set-Cookie"))


# --------------------------------------------------------------------------- #
# A1-b — los tokens salen por cookie, nunca por el cuerpo
# --------------------------------------------------------------------------- #
def test_a1b_login_emite_cookies_httponly_samesite(ciclo_de_sesion):
    cookies = _set_cookies(ciclo_de_sesion.login)
    for nombre in ("access_token", "refresh_token"):
        cabecera = next((c for c in cookies if c.startswith(nombre + "=")), None)
        assert cabecera is not None, (
            f"el login no emitió la cookie {nombre}; Set-Cookie recibidas: {cookies}"
        )
        bajo = cabecera.lower()
        assert "httponly" in bajo, (
            f"{nombre} sin HttpOnly: el JavaScript podría leer el token y A1 se "
            f"reabre (esto sería localStorage con más pasos). Cabecera: {cabecera}"
        )
        assert "samesite=strict" in bajo, (
            f"{nombre} sin SameSite=Strict: {cabecera}"
        )
        # `Secure` NO se afirma aquí a propósito: en stack_dev TLS=false (ver el
        # docstring del módulo). Es materia de stack_prod.


def test_a1b_el_cuerpo_del_login_no_lleva_tokens(ciclo_de_sesion):
    """El cuerpo no lleva los JWT. Si los devolviera, el frontend podría volver a
    guardarlos en localStorage y A1 quedaría abierto."""
    r = ciclo_de_sesion.login
    payload = r.json()

    assert payload.get("success") is True
    for prohibida in ("access", "refresh", "access_token", "refresh_token", "token"):
        assert prohibida not in payload, (
            f"el cuerpo del login expone '{prohibida}': los tokens deben viajar "
            "SÓLO como cookies HttpOnly (A1-b)."
        )

    # Contundente: el valor real del token no aparece por ningún lado del cuerpo.
    assert ciclo_de_sesion.access_1 and ciclo_de_sesion.access_1 not in r.text
    assert ciclo_de_sesion.refresh_1 and ciclo_de_sesion.refresh_1 not in r.text
    # Genérico, para cualquier token futuro: la cabecera de todo JWT en base64url
    # empieza por "eyJ" ({"). Si aparece uno en el cuerpo, algo lo está filtrando.
    assert "eyJ" not in r.text, (
        f"hay algo con forma de JWT en el cuerpo del login: {r.text[:300]}"
    )


def test_a1b_el_cuerpo_del_login_solo_lleva_datos_de_ui(ciclo_de_sesion):
    """Regresión de forma: el cuerpo son exactamente `success` y `user`.

    Hasta el 29 jul 2026 traía además `session`, que `SessionCreationMiddleware`
    añadía con el `session_id` del gestor de sesiones propio — el MISMO valor que
    fija acto seguido como cookie `HttpOnly`, con lo que la copia del cuerpo (que
    el JavaScript sí lee) anulaba ese HttpOnly. Se retiró: el navegador manda la
    cookie sola y la pantalla de seguridad usa `/api/sessions/list/`.

    Afirmar la forma exacta hace que una clave NUEVA —que sí podría llevar un
    token o un identificador de sesión— rompa el test el día que aparezca.
    """
    payload = ciclo_de_sesion.login.json()
    assert set(payload) == {"success", "user"}, (
        f"el cuerpo del login cambió de forma: {sorted(payload)}. Si vuelve "
        "`session`, se está republicando el session_id que la cookie protege con "
        "HttpOnly; si es otra clave, comprueba que no expone tokens (A1-b)."
    )
    assert "session_id" not in ciclo_de_sesion.login.text, (
        "el session_id vuelve a viajar en el cuerpo del login."
    )


# --------------------------------------------------------------------------- #
# N1 — /api/token/refresh/ existe y reescribe las cookies
# --------------------------------------------------------------------------- #
def test_n1_refresh_con_cookie_da_200_y_reescribe_cookies(ciclo_de_sesion):
    """Antes de la Fase 1 esta ruta no existía y el catch-all devolvía HTML con
    200: a los 60 min el access expiraba y el usuario se quedaba fuera."""
    r = ciclo_de_sesion.refresh

    assert r.status_code == 200, f"/api/token/refresh/ devolvió {r.status_code}: {r.text[:400]}"
    assert "text/html" not in r.headers.get("Content-Type", ""), (
        "la renovación devolvió HTML: el catch-all se está tragando la ruta (N1)."
    )
    assert r.json().get("success") is True

    cookies = _set_cookies(r)
    assert any(c.startswith("access_token=") for c in cookies), (
        f"la renovación no reescribió `access_token`: {cookies}"
    )
    assert ciclo_de_sesion.access_2 and ciclo_de_sesion.access_2 != ciclo_de_sesion.access_1, (
        "el access token no cambió tras renovar."
    )
    # ROTATE_REFRESH_TOKENS = True: el refresh también se reemplaza.
    assert any(c.startswith("refresh_token=") for c in cookies), (
        f"con ROTATE_REFRESH_TOKENS la renovación debe reescribir `refresh_token`: {cookies}"
    )
    assert ciclo_de_sesion.refresh_2 and ciclo_de_sesion.refresh_2 != ciclo_de_sesion.refresh_1, (
        "el refresh token no rotó (ROTATE_REFRESH_TOKENS)."
    )
    # El cuerpo tampoco lleva tokens en la renovación (misma regla que A1-b).
    assert ciclo_de_sesion.access_2 not in r.text


# --------------------------------------------------------------------------- #
# A5 — el logout invalida el refresh de verdad
# --------------------------------------------------------------------------- #
def test_a5_el_logout_responde_ok(ciclo_de_sesion):
    r = ciclo_de_sesion.logout
    assert r.status_code == 200, f"logout devolvió {r.status_code}: {r.text[:400]}"
    assert r.json().get("success") is True


def test_a5_refresh_reusado_tras_logout_da_401(ciclo_de_sesion):
    """Hasta la Fase 1 el logout no invalidaba nada: el refresh copiado seguía
    sirviendo 7 días. Ahora `SecureLogoutView` lo pone en `BlacklistedToken` y
    `CookieTokenRefreshView` lo rechaza.

    El token reusado es el que emitió la rotación de N1 unos milisegundos antes,
    así que sin el blacklist seguiría siendo válido: el 401 sólo puede venir del
    logout.
    """
    assert ciclo_de_sesion.refresh_2, (
        "no se capturó ningún refresh vivo antes del logout: sin él este test no "
        "estaría probando nada (un 401 podría venir de la falta de token)."
    )
    r = ciclo_de_sesion.reuso

    assert r.status_code == 401, (
        f"reusar el refresh tras el logout devolvió {r.status_code}, se esperaba 401 "
        f"(A5: el token debería estar en la blacklist). Cuerpo: {r.text[:400]}"
    )
    assert "text/html" not in r.headers.get("Content-Type", "")


# =========================================================================== #
# Z7 — la contraseña maestra nunca viaja
# =========================================================================== #
def test_z7_verify_acepta_solo_la_auth_key_derivada(auth_session, zk_user):
    """Prueba de posesión con la AuthKey derivada EN EL CLIENTE (aquí, en el
    contenedor: el host no tiene argon2-cffi). El cuerpo que sale por la red no
    contiene la maestra por ninguna parte.
    """
    session, base_url = auth_session
    cuerpo = {"auth_key": zk_user.material["auth_key"]}

    # La afirmación del criterio §10, sobre el cuerpo REAL que se va a enviar.
    serializado = json.dumps(cuerpo)
    assert zk_user.master_password not in serializado, (
        "la contraseña maestra aparece en el cuerpo de /api/master-key/verify/"
    )
    assert set(cuerpo) == {"auth_key"}

    r = session.post(
        base_url + "/api/master-key/verify/",
        data=serializado,
        headers=csrf_headers(session, base_url, {"Content-Type": "application/json"}),
        timeout=30,
    )

    if r.status_code == 429:
        pytest.skip(
            "cubo 'auth' agotado (10 peticiones/5 min por IP) o bloqueo exponencial "
            "de la maestra activo; espera y repite."
        )
    assert r.status_code == 200, (
        f"verify con la AuthKey derivada devolvió {r.status_code}: {r.text[:400]}"
    )
    assert r.json().get("success") is True


def test_z7_verify_rechaza_la_maestra_en_claro(auth_session, zk_user):
    """El servidor NO es un oráculo de la maestra: sólo sabe comprobar
    Argon2id(AuthKey). Mandar la contraseña maestra tal cual —lo que haría un
    cliente v1— no vale como prueba de posesión.

    Cuesta un fallo del bloqueo exponencial (4 gratis antes de penalizar) y el
    acierto del test anterior borra el contador de fallos consecutivos.
    """
    session, base_url = auth_session
    r = session.post(
        base_url + "/api/master-key/verify/",
        data=json.dumps({"auth_key": zk_user.master_password}),
        headers=csrf_headers(session, base_url, {"Content-Type": "application/json"}),
        timeout=30,
    )

    if r.status_code == 429:
        pytest.skip("cubo 'auth' agotado o bloqueo exponencial activo; espera y repite.")
    assert r.status_code == 400, (
        f"la maestra en claro devolvió {r.status_code}, se esperaba 400. "
        f"Un 200 significaría que el servidor la conoce (Z7 roto). Cuerpo: {r.text[:400]}"
    )
    assert r.json().get("success") is False


def test_z7_setup_exige_material_derivado(auth_session, zk_user):
    """El contrato de `/api/master-key/setup/` no tiene hueco para la maestra:
    exige kdf_salt + auth_key + wrapped_vault_key. Un cliente que intentara enviar
    la contraseña se estrella contra la validación de campos."""
    session, base_url = auth_session
    r = session.post(
        base_url + "/api/master-key/setup/",
        data=json.dumps({"master_password": zk_user.master_password}),
        headers=csrf_headers(session, base_url, {"Content-Type": "application/json"}),
        timeout=30,
    )

    assert r.status_code == 400, (
        f"setup con la maestra en claro devolvió {r.status_code}, se esperaba 400: "
        f"{r.text[:400]}"
    )
    payload = r.json()
    assert payload.get("success") is False
    assert "kdf_salt" in payload.get("error", ""), (
        f"el error debería nombrar el campo derivado que falta: {payload}"
    )


def test_z7_params_solo_devuelve_material_opaco(auth_session, zk_user):
    """El material de desbloqueo que el servidor entrega es opaco sin la maestra:
    kdf_salt, kdf_params y wrapped_vault_key. Ni la maestra ni la EncKey ni la
    VaultKey en claro salen de aquí."""
    session, base_url = auth_session
    r = session.get(base_url + "/api/master-key/params/", timeout=20)

    assert r.status_code == 200, f"params devolvió {r.status_code}: {r.text[:300]}"
    payload = r.json()
    assert set(payload) == {
        "success", "kdf_salt", "kdf_params", "wrapped_vault_key", "crypto_version"
    }, f"claves inesperadas en /api/master-key/params/: {sorted(payload)}"
    assert payload["kdf_salt"] == zk_user.material["kdf_salt"]
    assert payload["wrapped_vault_key"] == zk_user.material["wrapped_vault_key"]
    assert zk_user.master_password not in r.text, (
        "la contraseña maestra aparece en la respuesta de /api/master-key/params/"
    )
