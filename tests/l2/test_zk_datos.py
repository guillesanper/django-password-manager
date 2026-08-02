"""L2 · stack_dev · Los datos zero-knowledge por HTTP real.

  - A7        `GET /api/accounts/` devuelve `ciphertext` + `client_id`, NO las
              columnas v1 (encrypted_password / encrypted_key / iv_or_nonce / salt)
              ni nada en claro.
  - Z10 / M8  `POST /api/master-key/change/` RE-ENVUELVE la `wrapped_vault_key` y la
              bóveda sigue abriéndose con la maestra nueva, sin tocar un solo
              `ciphertext` de las entradas. Criterio §10 de la auditoría.
  - Z11 / A9  Bóveda privada BLOQUEADA -> `GET /api/vaults/<id>/passwords/` deniega;
              un `vault_already_unlocked: true` puesto por el cliente NO salta nada
              (ese flag de confianza se eliminó: ahora hay `sub_auth_key_hash` y un
              marcador que pone el SERVIDOR tras probar posesión de la subclave).
  - M3-a      `/api/password-generator/?count=100000&length=100000` -> 400, y
              `count=abc` -> 400 (no 500).
  - M9        Registro -> cuenta INACTIVA hasta verificar el email. **Sigue abierto**
              (Fase 3): xfail estricto, hoy el registro deja la cuenta activa.

Toda la cripto corre EN EL CONTENEDOR (§7.1: el host no tiene argon2-cffi ni
cryptography); el host sólo transporta base64 y hace las peticiones HTTP. Los blobs
que se descifran para comprobar Z10 son los que devolvió el SERVIDOR por HTTP, no
los que se sembraron: el ciclo se cierra de punta a punta.

L2 no tiene rollback (§6): la rotación de Z10 se deshace en el teardown de su
fixture y el usuario efímero de M9 se borra por ORM.
"""

import base64
import json

import pytest
import requests

from _l2lib import (
    CLEANUP_CODE,
    DECRYPT_CODE,
    L2_M9_EMAIL,
    L2_M9_FIRST_NAME,
    L2_M9_LAST_NAME,
    L2_M9_PASSWORD,
    L2_MASTER_PASSWORD_NUEVA,
    PROBE_USER_CODE,
    ROTATE_CODE,
    container_exec_python,
    container_output,
    csrf_headers,
    marked_json,
)

pytestmark = [pytest.mark.l2, pytest.mark.stack_dev]

# Columnas del esquema v1 (cifrado en servidor) que la Fase 2 purgó. Si alguna
# reaparece en la API, el material offline atacable vuelve a estar servido.
_COLUMNAS_V1 = {
    "encrypted_password", "encrypted_key", "iv_or_nonce", "salt",
    "password", "website", "username", "notes",
}
_CLAVES_ENTRADA_V2 = {
    "id", "client_id", "vault_id", "crypto_version", "ciphertext",
    "created_at", "updated_at",
}


def _cuentas(session, base_url):
    """`GET /api/accounts/` -> (respuesta, {client_id: entrada})."""
    r = session.get(base_url + "/api/accounts/", timeout=30)
    assert r.status_code == 200, f"/api/accounts/ devolvió {r.status_code}: {r.text[:400]}"
    return r, {a.get("client_id"): a for a in r.json().get("accounts", [])}


# =========================================================================== #
# A7 — la API sólo entrega blobs opacos
# =========================================================================== #
def test_a7_accounts_devuelve_ciphertext_y_client_id(auth_session, zk_user):
    session, base_url = auth_session
    _r, por_cid = _cuentas(session, base_url)

    cid = zk_user.material["entry_client_id"]
    assert cid in por_cid, (
        f"la entrada sembrada ({cid}) no aparece en /api/accounts/: {sorted(por_cid)}"
    )
    entrada = por_cid[cid]

    assert set(entrada) == _CLAVES_ENTRADA_V2, (
        f"la forma de la entrada cambió: {sorted(entrada)}"
    )
    assert entrada["ciphertext"], "la entrada no trae ciphertext"
    assert entrada["crypto_version"] == 2
    assert not (set(entrada) & _COLUMNAS_V1), (
        f"reaparecieron columnas v1 en la API: {sorted(set(entrada) & _COLUMNAS_V1)}"
    )


def test_a7_accounts_no_filtra_texto_claro(auth_session, zk_user):
    """El sitio y el usuario de la entrada viajan DENTRO del blob cifrado: el
    servidor no los conoce y por tanto no puede devolverlos."""
    session, base_url = auth_session
    r, _por_cid = _cuentas(session, base_url)

    for claro in (zk_user.material["entry_website"], "l2-cuenta", "Blob$Opaco9zk"):
        assert claro not in r.text, (
            f"/api/accounts/ devolvió texto claro ({claro!r}): la entrada no está "
            "realmente cifrada extremo a extremo (A7)."
        )


# =========================================================================== #
# Z10 / M8 — rotar la maestra re-envuelve, no re-cifra
# =========================================================================== #
def _rotar_material(compose_cmd, backend_dir, email, actual, nueva):
    """Deriva en el contenedor el cuerpo de /api/master-key/change/.

    Espejo de `rotateMasterPassword`: desenvuelve la VaultKey con la EncKey ACTUAL
    y la re-envuelve con la NUEVA. La VaultKey no cambia, luego las entradas no
    necesitan re-cifrarse (que es justo lo que M8 afirma).
    """
    res = container_exec_python(
        compose_cmd, backend_dir, ROTATE_CODE,
        seed_env={"SEED_EMAIL": email, "CUR_MASTER_PWD": actual, "NEW_MASTER_PWD": nueva},
    )
    material = marked_json(res, "ROTATE_JSON")
    if material is None:
        pytest.skip(
            "No se pudo derivar el material de rotación en el contenedor. "
            f"rc={res.returncode}. Salida:\n{container_output(res)}"
        )
    return material


def _cambiar_maestra(session, base_url, material):
    return session.post(
        base_url + "/api/master-key/change/",
        data=json.dumps(material),
        headers=csrf_headers(session, base_url, {"Content-Type": "application/json"}),
        timeout=60,
    )


def _descifrar_en_contenedor(compose_cmd, backend_dir, maestra, kdf_salt, wrapped,
                             ciphertext, aad):
    """Deriva desde CERO con la maestra y descifra el blob que devolvió el servidor.

    Sólo entra lo que se recibió por HTTP: nada se lee de la BD ni del sembrado, así
    que el resultado no puede ser circular.
    """
    res = container_exec_python(
        compose_cmd, backend_dir, DECRYPT_CODE,
        seed_env={
            "MASTER_PWD": maestra,
            "KDF_SALT": kdf_salt,
            "WRAPPED_VAULT_KEY": wrapped,
            "CIPHERTEXT": ciphertext,
            "ENTRY_AAD": aad,
        },
    )
    payload = marked_json(res, "DECRYPT_JSON")
    assert payload is not None, (
        "no se pudo desbloquear la bóveda con la maestra nueva tras la rotación "
        f"(Z10/M8). rc={res.returncode}. Salida:\n{container_output(res)}"
    )
    return base64.b64decode(payload["plaintext_b64"]).decode("utf-8")


@pytest.fixture(scope="module")
def maestra_rotada(auth_session, zk_user, compose_cmd, backend_dir):
    """Rota la maestra a otra distinta y la devuelve a la original al terminar.

    El teardown restaura para que el resto de la suite (y una segunda pasada, §6)
    encuentre el material del fixture tal y como lo dejó el sembrado.
    """
    session, base_url = auth_session
    _r, antes = _cuentas(session, base_url)

    nuevo = _rotar_material(
        compose_cmd, backend_dir, zk_user.email,
        zk_user.master_password, L2_MASTER_PASSWORD_NUEVA,
    )
    respuesta = _cambiar_maestra(session, base_url, nuevo)

    try:
        yield {"antes": antes, "nuevo": nuevo, "respuesta": respuesta}
    finally:
        if respuesta.status_code == 200:
            vuelta = _rotar_material(
                compose_cmd, backend_dir, zk_user.email,
                L2_MASTER_PASSWORD_NUEVA, zk_user.master_password,
            )
            restaurada = _cambiar_maestra(session, base_url, vuelta)
            assert restaurada.status_code == 200, (
                "no se pudo restaurar la contraseña maestra original tras Z10 "
                f"({restaurada.status_code}): {restaurada.text[:400]}. El usuario de "
                "test queda con la maestra rotada; bórralo y vuelve a sembrar."
            )


def test_z10_el_cambio_de_maestra_se_acepta(maestra_rotada):
    r = maestra_rotada["respuesta"]
    if r.status_code == 429:
        pytest.skip(
            "429 en /api/master-key/change/: cubo 'sensitive' (70/h) agotado o "
            f"bloqueo exponencial de la maestra activo. Cuerpo: {r.text[:200]}"
        )
    assert r.status_code == 200, (
        f"/api/master-key/change/ devolvió {r.status_code}: {r.text[:400]}"
    )
    assert r.json().get("success") is True


def test_z10_el_servidor_guarda_el_material_nuevo(maestra_rotada, auth_session):
    """La rotación reemplaza kdf_salt + wrapped_vault_key + auth_key_hash; el
    servidor no ha visto ninguna de las dos contraseñas maestras."""
    if maestra_rotada["respuesta"].status_code != 200:
        pytest.skip("la rotación no se aplicó; ver test_z10_el_cambio_de_maestra_se_acepta")

    session, base_url = auth_session
    r = session.get(base_url + "/api/master-key/params/", timeout=20)
    assert r.status_code == 200, f"params devolvió {r.status_code}: {r.text[:300]}"
    params = r.json()

    assert params["kdf_salt"] == maestra_rotada["nuevo"]["kdf_salt"]
    assert params["wrapped_vault_key"] == maestra_rotada["nuevo"]["wrapped_vault_key"]
    assert L2_MASTER_PASSWORD_NUEVA not in r.text, (
        "la contraseña maestra nueva aparece en la respuesta del servidor"
    )


def test_z10_los_ciphertext_de_las_entradas_no_se_tocan(maestra_rotada, auth_session):
    """M8: rotar NO re-cifra la bóveda. Se compara `ciphertext` **y** `updated_at`:
    si el servidor hubiera reescrito las filas, `auto_now` lo delataría aunque el
    blob resultante fuese idéntico."""
    if maestra_rotada["respuesta"].status_code != 200:
        pytest.skip("la rotación no se aplicó; ver test_z10_el_cambio_de_maestra_se_acepta")

    session, base_url = auth_session
    _r, despues = _cuentas(session, base_url)
    antes = maestra_rotada["antes"]

    assert set(despues) == set(antes), (
        "la rotación cambió el conjunto de entradas: "
        f"antes {sorted(antes)}, después {sorted(despues)}"
    )
    for cid, entrada in antes.items():
        assert despues[cid]["ciphertext"] == entrada["ciphertext"], (
            f"la entrada {cid} se re-cifró al rotar la maestra: M8 dice que la "
            "VaultKey no cambia, así que el ciphertext tampoco."
        )
        assert despues[cid]["updated_at"] == entrada["updated_at"], (
            f"la fila de la entrada {cid} se reescribió al rotar (updated_at cambió)."
        )


def test_z10_la_boveda_sigue_abriendose_con_la_maestra_nueva(
    maestra_rotada, auth_session, zk_user, compose_cmd, backend_dir
):
    """El criterio §10 completo: con SÓLO la contraseña maestra nueva y el material
    que devuelve el servidor, se desenvuelve la MISMA VaultKey y se descifra una
    entrada creada ANTES de la rotación."""
    if maestra_rotada["respuesta"].status_code != 200:
        pytest.skip("la rotación no se aplicó; ver test_z10_el_cambio_de_maestra_se_acepta")

    session, base_url = auth_session
    params = session.get(base_url + "/api/master-key/params/", timeout=20).json()
    _r, despues = _cuentas(session, base_url)

    cid = zk_user.material["entry_client_id"]
    entrada = despues[cid]
    aad = f"{zk_user.material['user_id']}|{cid}|{entrada['crypto_version']}"

    plano = _descifrar_en_contenedor(
        compose_cmd, backend_dir,
        maestra=L2_MASTER_PASSWORD_NUEVA,
        kdf_salt=params["kdf_salt"],
        wrapped=params["wrapped_vault_key"],
        ciphertext=entrada["ciphertext"],
        aad=aad,
    )

    assert plano == zk_user.material["entry_plaintext"], (
        "el texto claro recuperado tras la rotación no es el original: la rotación "
        "no preservó la VaultKey (Z10/M8)."
    )


# =========================================================================== #
# Z11 / A9 — la bóveda privada deniega mientras está bloqueada
# =========================================================================== #
@pytest.fixture(scope="module")
def boveda_bloqueada(auth_session, zk_user):
    """Captura de una vez el estado BLOQUEADO de la bóveda privada sembrada.

    Se graba antes de que ningún test pueda desbloquearla: el fixture se ejecuta
    en el primer test que lo pida, así que las capturas son siempre previas al
    desbloqueo aunque se seleccione un subconjunto de tests o cambie el orden.

    La bóveda nace bloqueada porque el marcador de desbloqueo sólo lo pone el
    servidor tras verificar la SubAuthKey (paso 24); sembrar por ORM no lo pone.
    """
    session, base_url = auth_session
    vault_id = zk_user.material["vault_id"]
    ruta = base_url + f"/api/vaults/{vault_id}/passwords/"
    cabeceras_json = {"Content-Type": "application/json"}

    capturas = {
        "cuentas": session.get(base_url + "/api/accounts/", timeout=30),
        "passwords": session.get(ruta, timeout=30),
        # El viejo flag de confianza del cliente, por los dos caminos por los que
        # llegaba: query string y cuerpo.
        "flag_query": session.get(ruta + "?vault_already_unlocked=true", timeout=30),
        "flag_cuerpo": session.get(
            ruta,
            data=json.dumps({"vault_already_unlocked": True}),
            headers=cabeceras_json,
            timeout=30,
        ),
        # Y el mismo flag intentando pasar por prueba de posesión en el desbloqueo.
        "unlock_con_flag": session.post(
            base_url + f"/api/vaults/{vault_id}/unlock/",
            data=json.dumps({"vault_already_unlocked": True}),
            headers=csrf_headers(session, base_url, cabeceras_json),
            timeout=30,
        ),
    }
    return session, base_url, vault_id, capturas


def test_z11_boveda_privada_bloqueada_deniega(boveda_bloqueada):
    _s, _b, _vid, capturas = boveda_bloqueada
    r = capturas["passwords"]

    assert r.status_code == 403, (
        f"la bóveda privada bloqueada devolvió {r.status_code}, se esperaba 403 "
        f"(A9). Cuerpo: {r.text[:400]}"
    )
    payload = r.json()
    assert payload.get("code") == "VAULT_LOCKED", f"código inesperado: {payload}"
    assert "passwords" not in payload, "se entregaron entradas de una bóveda bloqueada"


@pytest.mark.parametrize("via", ["flag_query", "flag_cuerpo"])
def test_z11_el_flag_del_cliente_no_abre_la_boveda(boveda_bloqueada, via):
    """`vault_already_unlocked: true` era un booleano de confianza que cualquiera
    con una sesión podía poner a mano. Se eliminó: hoy el gate es un marcador que
    pone el servidor tras `guard_vault_auth_key`."""
    _s, _b, _vid, capturas = boveda_bloqueada
    r = capturas[via]

    assert r.status_code == 403, (
        f"con vault_already_unlocked=true por {via} la bóveda devolvió "
        f"{r.status_code}: el flag del cliente NO puede saltarse el gate (A9). "
        f"Cuerpo: {r.text[:400]}"
    )
    assert r.json().get("code") == "VAULT_LOCKED"


def test_z11_el_flag_no_sirve_como_prueba_en_el_desbloqueo(boveda_bloqueada):
    """`/api/vaults/<id>/unlock/` exige la SubAuthKey derivada de la contraseña del
    vault; sin ella no hay desbloqueo posible."""
    _s, _b, _vid, capturas = boveda_bloqueada
    r = capturas["unlock_con_flag"]

    assert r.status_code == 400, (
        f"el desbloqueo con el flag devolvió {r.status_code}, se esperaba 400 "
        f"(falta la prueba de posesión). Cuerpo: {r.text[:400]}"
    )
    assert r.json().get("success") is False


def test_z11_accounts_oculta_las_entradas_de_una_privada_bloqueada(boveda_bloqueada, zk_user):
    """Defensa en profundidad: `/api/accounts/` ni siquiera entrega el ciphertext
    de una bóveda privada que no se ha desbloqueado."""
    _s, _b, _vid, capturas = boveda_bloqueada
    r = capturas["cuentas"]
    assert r.status_code == 200

    cids = {a.get("client_id") for a in r.json().get("accounts", [])}
    assert zk_user.material["vault_entry_client_id"] not in cids, (
        "la entrada de la bóveda privada BLOQUEADA aparece en /api/accounts/ (A9)."
    )
    # La entrada sin bóveda sí debe estar: el filtro es de la privada, no de todo.
    assert zk_user.material["entry_client_id"] in cids


def test_z11_con_la_subclave_correcta_la_boveda_abre(boveda_bloqueada, zk_user):
    """Control positivo: probada la posesión de la subclave, el servidor pone el
    marcador y entrega los blobs — que siguen siendo opacos (cifrados bajo la
    VaultSubKey, que el servidor tampoco tiene)."""
    session, base_url, vault_id, _capturas = boveda_bloqueada

    r = session.post(
        base_url + f"/api/vaults/{vault_id}/unlock/",
        data=json.dumps({"sub_auth_key": zk_user.material["vault_sub_auth_key"]}),
        headers=csrf_headers(session, base_url, {"Content-Type": "application/json"}),
        timeout=30,
    )
    assert r.status_code == 200, (
        f"el desbloqueo con la SubAuthKey correcta devolvió {r.status_code}: {r.text[:400]}"
    )

    r2 = session.get(base_url + f"/api/vaults/{vault_id}/passwords/", timeout=30)
    assert r2.status_code == 200, (
        f"tras desbloquear, la bóveda devolvió {r2.status_code}: {r2.text[:400]}"
    )
    payload = r2.json()
    cids = {p.get("client_id") for p in payload.get("passwords", [])}
    assert zk_user.material["vault_entry_client_id"] in cids, (
        "la bóveda desbloqueada no devolvió su entrada"
    )
    assert zk_user.material["vault_entry_website"] not in r2.text, (
        "la bóveda desbloqueada devolvió texto claro: el contenido debe seguir "
        "cifrado bajo la VaultSubKey (el servidor no la tiene)."
    )


# =========================================================================== #
# M3-a — el generador acota sus parámetros
# =========================================================================== #
@pytest.mark.parametrize(
    "query,motivo",
    [
        ("count=100000&length=100000", "cota superior: bloquearía un worker entero"),
        ("count=abc", "no numérico: antes reventaba con ValueError -> 500"),
        ("length=abc", "no numérico en length"),
        ("count=0", "cota inferior"),
    ],
)
def test_m3a_el_generador_rechaza_parametros_fuera_de_rango(auth_session, query, motivo):
    session, base_url = auth_session
    r = session.get(base_url + f"/api/password-generator/?{query}", timeout=30)

    assert r.status_code == 400, (
        f"?{query} devolvió {r.status_code}, se esperaba 400 ({motivo}). "
        f"Cuerpo: {r.text[:300]}"
    )
    assert r.status_code != 500
    payload = r.json()
    assert payload.get("success") is False
    assert payload.get("error"), "el 400 debe explicar el parámetro y sus límites"


def test_m3a_el_generador_sigue_funcionando_dentro_de_rango(auth_session):
    """Control: acotar no es romper. 5 contraseñas de 20 caracteres siguen saliendo."""
    session, base_url = auth_session
    r = session.get(base_url + "/api/password-generator/?count=5&length=20", timeout=30)

    assert r.status_code == 200, f"devolvió {r.status_code}: {r.text[:300]}"
    passwords = r.json()["passwords"]
    assert len(passwords) == 5
    assert all(len(p) == 20 for p in passwords)


# =========================================================================== #
# M9 — registro sin verificación de email (ABIERTO, Fase 3)
# =========================================================================== #
@pytest.fixture(scope="module")
def usuario_recien_registrado(base_url, compose_cmd, backend_dir):
    """Registra por HTTP una cuenta efímera y la borra al terminar.

    Se limpia ANTES también: si una corrida anterior murió sin teardown, el email
    ya existiría y el registro daría 400.
    """
    entorno = {"SEED_EMAIL": L2_M9_EMAIL}
    container_exec_python(compose_cmd, backend_dir, CLEANUP_CODE, seed_env=entorno)

    s = requests.Session()
    s.verify = False
    try:
        r_csrf = s.get(base_url + "/api/csrf/", timeout=20)
        assert r_csrf.status_code == 200, f"/api/csrf/ devolvió {r_csrf.status_code}"

        r = s.post(
            base_url + "/auth/register/",
            data=json.dumps({
                "first_name": L2_M9_FIRST_NAME,
                "last_name": L2_M9_LAST_NAME,
                "email": L2_M9_EMAIL,
                "password": L2_M9_PASSWORD,
            }),
            headers=csrf_headers(s, base_url, {"Content-Type": "application/json"}),
            timeout=30,
        )
        if r.status_code != 200:
            # 429/403: el registro está limitado a 3 por hora e IP (y 8/h por
            # django_ratelimit). No es el hallazgo que se mide aquí -> se salta.
            pytest.skip(
                f"no se pudo registrar la cuenta de sondeo ({r.status_code}): "
                f"{r.text[:300]}"
            )
        yield L2_M9_EMAIL
    finally:
        s.close()
        container_exec_python(compose_cmd, backend_dir, CLEANUP_CODE, seed_env=entorno)


@pytest.mark.fase3
@pytest.mark.xfail(
    strict=True,
    reason="M9 — el registro deja la cuenta ACTIVA: falta la verificación de email "
           "(y el TOTP desde IP nueva). Cierra en Fase 3.",
)
def test_m9_el_registro_deja_la_cuenta_inactiva(
    usuario_recien_registrado, compose_cmd, backend_dir
):
    """Debe FALLAR hoy. Hoy `SecureRegisterView` crea el usuario con `is_active`
    por defecto (True) y además lo autentica en el acto: quien registra un email
    ajeno queda dentro sin demostrar que lo controla.

    Cuando la Fase 3 lo cierre, este test pasará y el `xfail_strict` del pytest.ini
    pondrá la suite en rojo hasta que se retire el marcador (§3).
    """
    res = container_exec_python(
        compose_cmd, backend_dir, PROBE_USER_CODE,
        seed_env={"SEED_EMAIL": usuario_recien_registrado},
    )
    sonda = marked_json(res, "PROBE_JSON")
    assert sonda is not None, (
        f"no se pudo sondear la cuenta en el contenedor. rc={res.returncode}. "
        f"Salida:\n{container_output(res)}"
    )
    assert sonda["exists"] is True, "el registro no creó la cuenta"
    assert sonda["is_active"] is False, (
        "la cuenta recién registrada está ACTIVA sin verificar el email (M9)."
    )
