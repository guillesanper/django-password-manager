"""Infraestructura compartida de L2 (integración por HTTP real contra la pila).

L2 corre en el HOST con un cliente HTTP (§2.1 del PLAN-DE-PRUEBAS.md): NO importa
Django (settings.py:39 exige DJANGO_SECRET_KEY y minio_service instancia MinIO a
nivel de módulo). Todo lo que necesita del ORM se hace DENTRO del contenedor `web`
vía `docker compose exec` (sembrado y limpieza de usuarios de test).

Aquí viven la DETECCIÓN de pila, el hook de SKIP de la pila contraria (trampa 1) y
las FIXTURES. Los helpers puros (compose, sembrado, CSRF, flush de Redis) están en
`_l2lib.py`, importable sin chocar con el conftest de la raíz.

Reglas duras (§6): L2 no tiene rollback (teardown borra usuario + cascada + bucket);
prohibido pytest-xdist (estado global de rate limit en Redis).
"""

import functools
import json

import pytest
import urllib3

# Certificado de nginx autofirmado (dev): se calla el aviso una sola vez (trampa 5).
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

import requests  # noqa: E402  (tras disable_warnings, a propósito)

from _l2lib import (  # noqa: E402
    BASE_URL_DEV,
    BASE_URL_PROD,
    CLEANUP_CODE,
    L2_DJANGO_PASSWORD,
    L2_EMAIL,
    L2_MASTER_PASSWORD,
    L2_USERNAME,
    L2_VAULT_PASSWORD,
    L2User,
    SEED_CODE,
    _DEV_PORT,
    _PROD_PORT,
    container_exec_python,
    container_output,
    csrf_headers,
    esperar_pila_lista,
    marked_json,
    port_open,
)


# =========================================================================== #
# Detección de la pila levantada (trampa 1)
# =========================================================================== #
# stack_dev  -> el override publica 127.0.0.1:8000 (web:8000 directo).
# stack_prod -> sólo nginx publica 80/443; el 8000 NO está publicado.
# Por tanto: 8000 abierto => dev; si no, 443 abierto => prod; si no, ninguna.
@functools.lru_cache(maxsize=1)
def _detect_stack():
    """'stack_dev' | 'stack_prod' | None. Cacheado: una sola sonda por sesión."""
    if port_open(_DEV_PORT):
        return "stack_dev"
    if port_open(_PROD_PORT):
        return "stack_prod"
    return None


def pytest_runtest_setup(item):
    """Salta (NO falla) los tests cuya pila no es la levantada (§6, trampa 1)."""
    detected = _detect_stack()
    wants_prod = item.get_closest_marker("stack_prod") is not None
    wants_dev = item.get_closest_marker("stack_dev") is not None

    if wants_prod and detected != "stack_prod":
        pytest.skip(
            "requiere stack_prod (docker compose -f docker-compose.yml up -d --build); "
            f"detectado: {detected or 'ninguna pila'}"
        )
    if wants_dev and detected != "stack_dev":
        pytest.skip(
            f"requiere stack_dev (docker compose up -d); detectado: {detected or 'ninguna pila'}"
        )


# =========================================================================== #
# Fixtures de pila
# =========================================================================== #
@pytest.fixture(scope="session")
def stack():
    """Nombre de la pila levantada. Los tests ya vienen filtrados por el hook."""
    detected = _detect_stack()
    if detected is None:
        pytest.skip("ninguna pila levantada")
    return detected


@pytest.fixture(scope="session")
def backend_dir(repo_root):
    """Directorio backend/ (donde viven docker-compose.yml y .env)."""
    return repo_root / "backend"


@pytest.fixture(scope="session")
def base_url(stack):
    """URL base HTTPS (prod, por nginx) o HTTP (dev, web:8000 directo).

    Antes de devolverla se espera a que la pila CONTESTE (`/health/`): el puerto
    publicado se abre en cuanto arranca el contenedor, mucho antes de que la
    aplicación escuche, y lanzar pytest en esa ventana hace fallar el bloque
    entero con `RemoteDisconnected` por una razón ajena a lo que se prueba.
    """
    url = BASE_URL_PROD if stack == "stack_prod" else BASE_URL_DEV
    esperar_pila_lista(url)
    return url


@pytest.fixture(scope="session")
def compose_cmd(stack):
    """Prefijo de `docker compose` que targetea la pila levantada.

    stack_prod se estrena con `docker compose -f docker-compose.yml up`, SIN el
    override; se apunta con el mismo -f para no re-aplicarlo. stack_dev es a secas
    (override automático).
    """
    if stack == "stack_prod":
        return ["docker", "compose", "-f", "docker-compose.yml"]
    return ["docker", "compose"]


@pytest.fixture
def http():
    """Session requests nueva por test, con verify=False (autofirmado, trampa 5)."""
    s = requests.Session()
    s.verify = False
    try:
        yield s
    finally:
        s.close()


# =========================================================================== #
# Usuario ZK sembrado por ORM en el contenedor (trampa 7); sin rollback (§6)
# =========================================================================== #
@pytest.fixture(scope="session")
def zk_user(compose_cmd, backend_dir):
    """Siembra usuario + UserCrypto por ORM en el contenedor y lo borra al final.

    Session-scoped a propósito: sembrar deriva Argon2id (64 MiB) varias veces y no
    interesa repetirlo por test. El teardown arrastra la cascada (UserCrypto,
    PasswordEntry, Vault, EncryptedFile) y los objetos del bucket de MinIO (L2 no
    tiene rollback, §6).

    Desde la tanda 10 el sembrado devuelve además el MATERIAL ZK ya derivado
    (`L2User.material`): el host no puede derivar una AuthKey (no tiene
    argon2-cffi, §7.1), así que sólo transporta el base64 que produjo el
    contenedor.
    """
    seed_env = {
        "SEED_USERNAME": L2_USERNAME,
        "SEED_EMAIL": L2_EMAIL,
        "SEED_DJANGO_PWD": L2_DJANGO_PASSWORD,
        "SEED_MASTER_PWD": L2_MASTER_PASSWORD,
        "SEED_VAULT_PWD": L2_VAULT_PASSWORD,
    }
    res = container_exec_python(compose_cmd, backend_dir, SEED_CODE, seed_env=seed_env)
    out = (res.stdout or "") + (res.stderr or "")
    if "SEED_OK" not in out:
        pytest.skip(
            "No se pudo sembrar el usuario de test por ORM en el contenedor `web`. "
            f"rc={res.returncode}. Salida:\n{container_output(res)}"
        )
    user_id = None
    for line in (res.stdout or "").splitlines():
        if line.startswith("SEED_OK"):
            parts = line.split()
            if len(parts) >= 2 and parts[1].isdigit():
                user_id = int(parts[1])

    material = marked_json(res, "SEED_JSON")
    if material is None:
        pytest.skip(
            "El sembrado no emitió SEED_JSON (material ZK). "
            f"rc={res.returncode}. Salida:\n{container_output(res)}"
        )

    yield L2User(
        user_id=user_id,
        email=L2_EMAIL,
        username=L2_USERNAME,
        django_password=L2_DJANGO_PASSWORD,
        master_password=L2_MASTER_PASSWORD,
        vault_password=L2_VAULT_PASSWORD,
        material=material,
    )

    # Teardown: borrado del usuario + cascada + objetos de MinIO.
    container_exec_python(
        compose_cmd, backend_dir, CLEANUP_CODE, seed_env={"SEED_EMAIL": L2_EMAIL}
    )


@pytest.fixture(scope="session")
def auth_session(zk_user, base_url):
    """requests.Session autenticada: GET /api/csrf/ + POST /auth/login/.

    Devuelve (session, base_url). Las cookies HttpOnly (access_token/refresh) y la
    csrftoken quedan en la session. Un único login por sesión de tests para no
    gastar el presupuesto de auth de nginx (5r/m en /auth/login/).
    """
    session = requests.Session()
    session.verify = False

    r = session.get(base_url + "/api/csrf/", timeout=15)
    assert r.status_code == 200, f"/api/csrf/ devolvió {r.status_code}"
    assert session.cookies.get("csrftoken"), "no llegó la cookie csrftoken"

    r = session.post(
        base_url + "/auth/login/",
        data=json.dumps({"email": zk_user.email, "password": zk_user.django_password}),
        headers=csrf_headers(session, base_url, {"Content-Type": "application/json"}),
        timeout=20,
    )
    assert r.status_code == 200, f"login falló ({r.status_code}): {r.text[:500]}"
    assert session.cookies.get("access_token"), "el login no fijó la cookie access_token"

    try:
        yield session, base_url
    finally:
        session.close()
