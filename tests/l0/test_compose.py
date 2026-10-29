"""
L0 · Docker Compose base  —  A10-a y A11-a del inventario (§4.3 PLAN-DE-PRUEBAS.md)

Se parsea `backend/docker-compose.yml` con `yaml.safe_load` (vía `read_repo_text`),
NUNCA se importa Django ni se levanta la pila. Las aserciones son sobre el fichero
**BASE**, no sobre `docker-compose.override.yml`: el override abre puertos en
desarrollo a propósito (trampa 1), así que un test de superficie de red debe mirar
sólo el base, que es el que gobierna `stack_prod`.

  A10-a — superficie de red y secretos del compose:
    · sólo `nginx` publica `ports` (80/443); ningún otro servicio lo hace.
    · redis arranca con `--requirepass ${REDIS_PASSWORD}`.
    · ningún secreto va como literal: todos por interpolación `${...}`; los de
      MinIO y GRAFANA_ADMIN_PASSWORD en la forma obligatoria `${VAR:?...}` (sin
      default); ningún secreto usa el default inseguro `${VAR:-literal}`.

  A11-a — endurecimiento del servicio `web` en el base:
    · gunicorn con `--workers 3`.
    · sin `ports` (sólo alcanzable vía nginx).
    · sin el bind-mount de código `.:/usr/src/app` (sólo el volumen de logs).
    · sin fijar DEBUG (no trae `environment` con DJANGO_DEBUG/DEBUG=1; eso vive
      únicamente en el override).
"""

import re

import pytest
import yaml

pytestmark = pytest.mark.l0

_COMPOSE_REL = "backend/docker-compose.yml"

# Servicios del base cuyos secretos se vigilan. GRAFANA_ADMIN_USER queda fuera a
# propósito: es un NOMBRE de usuario, no un secreto, y usa `${VAR:-admin}` (default
# legítimo). Los seis de abajo SÍ son material sensible.
_STRICT_SECRETS = (
    "MINIO_ROOT_USER",
    "MINIO_ROOT_PASSWORD",
    "MINIO_KMS_SECRET_KEY",
    "GRAFANA_ADMIN_PASSWORD",
)
_PLAIN_SECRETS = (
    "POSTGRES_PASSWORD",
    "REDIS_PASSWORD",
)
_ALL_SECRETS = _STRICT_SECRETS + _PLAIN_SECRETS


@pytest.fixture(scope="module")
def compose(read_repo_text):
    """El compose BASE parseado. `safe_load` no ejecuta nada del YAML."""
    return yaml.safe_load(read_repo_text(_COMPOSE_REL))


@pytest.fixture(scope="module")
def services(compose):
    svcs = compose.get("services")
    assert isinstance(svcs, dict) and svcs, "El compose base no declara `services`."
    return svcs


def _env_items(service: dict):
    """
    Normaliza `environment` (dict o lista `KEY=value`) a pares (clave, valor).
    En el compose base conviven ambas formas: dict en redis/minio/grafana, lista
    en webhook-collector.
    """
    env = service.get("environment")
    if env is None:
        return []
    if isinstance(env, dict):
        return [(str(k), "" if v is None else str(v)) for k, v in env.items()]
    items = []
    for entry in env:
        text = str(entry)
        key, _, value = text.partition("=")
        items.append((key, value))
    return items


# =====================================================================
# A10-a — superficie de red: sólo nginx publica puertos
# =====================================================================

def test_a10a_solo_nginx_publica_puertos(services):
    con_ports = {name for name, svc in services.items()
                 if isinstance(svc, dict) and "ports" in svc}
    assert con_ports == {"nginx"}, (
        f"En el compose base sólo `nginx` debe publicar `ports`; lo hacen: "
        f"{sorted(con_ports)}. Cualquier otro servicio con `ports` expone un "
        "puerto interno al host (A10)."
    )


def test_a10a_nginx_publica_80_y_443(services):
    ports = services["nginx"].get("ports")
    assert isinstance(ports, list), "nginx.ports no es una lista."
    # yaml carga "80:80" como string; normalizamos por si alguno llega como int.
    mapeos = {str(p) for p in ports}
    assert "80:80" in mapeos, f"nginx no publica 80:80 (tiene {sorted(mapeos)}) (A10)."
    assert "443:443" in mapeos, (
        f"nginx no publica 443:443 (tiene {sorted(mapeos)}) (A10)."
    )


# =====================================================================
# A10-a — redis exige contraseña
# =====================================================================

def test_a10a_redis_requirepass(services):
    redis = services.get("redis")
    assert isinstance(redis, dict), "No hay servicio `redis` en el base."
    command = redis.get("command")
    assert command is not None, "redis no declara `command`."
    text = command if isinstance(command, str) else " ".join(map(str, command))
    assert "--requirepass ${REDIS_PASSWORD}" in text, (
        "redis no arranca con `--requirepass ${REDIS_PASSWORD}`: la cache/rate-limit "
        f"quedaría sin autenticar. command = {text!r} (A10)."
    )


# =====================================================================
# A10-a — ningún secreto como literal; formas de interpolación correctas
# =====================================================================

def _interpolations(text: str, var: str):
    """
    Devuelve todas las referencias `${VAR...}` a `var` en `text`, como la tripla
    (completo, operador, resto). El operador es '' (`${VAR}`), ':?' (obligatoria)
    o ':-' (default). Se busca la variable *interpolada*, no la clave del
    `environment`: p. ej. GRAFANA_ADMIN_PASSWORD es la variable `.env` referida
    dentro del valor de la clave `GF_SECURITY_ADMIN_PASSWORD`, y POSTGRES_PASSWORD
    aparece embebida en la URL del webhook-collector.
    """
    pattern = r"\$\{%s(:\?|:-)?([^}]*)\}" % re.escape(var)
    return [(m.group(0), m.group(1) or "", m.group(2)) for m in re.finditer(pattern, text)]


def test_a10a_secretos_por_interpolacion(read_repo_text):
    """
    Cada secreto vigilado se referencia por interpolación `${...}` y NUNCA aparece
    como literal. Se escanea el texto del compose por la variable interpolada, no
    por la clave del `environment` (que puede diferir del nombre de la variable).
    """
    source = read_repo_text(_COMPOSE_REL)
    for var in _ALL_SECRETS:
        refs = _interpolations(source, var)
        assert refs, (
            f"El secreto {var} no aparece interpolado (`${{{var}...}}`) en el compose "
            "base: ¿va como literal, o se renombró el servicio? (A10)."
        )


def test_a10a_minio_y_grafana_admin_sin_default(read_repo_text):
    """
    MinIO (root user/password, KMS) y GRAFANA_ADMIN_PASSWORD usan la forma
    obligatoria `${VAR:?mensaje}`: si falta la variable, Compose aborta en vez de
    arrancar con un valor por defecto conocido (A10).
    """
    source = read_repo_text(_COMPOSE_REL)
    for var in _STRICT_SECRETS:
        refs = _interpolations(source, var)
        assert refs, f"No se encuentra `${{{var}...}}` en el compose base."
        for completo, operador, _ in refs:
            assert operador == ":?", (
                f"{var} debe usar la forma obligatoria ${{{var}:?...}} (sin default); "
                f"aparece como {completo!r} (A10)."
            )


def test_a10a_ningun_secreto_con_default_inseguro(read_repo_text):
    """
    Ningún secreto usa el default inseguro `${VAR:-literal}`. GRAFANA_ADMIN_USER
    (`${GRAFANA_ADMIN_USER:-admin}`) es un NOMBRE de usuario, no un secreto, así
    que su default está permitido y no se marca.
    """
    source = read_repo_text(_COMPOSE_REL)
    for var in _ALL_SECRETS:
        for completo, operador, _ in _interpolations(source, var):
            assert operador != ":-", (
                f"{var} usa un default inseguro ({completo!r}): un secreto con valor "
                "por defecto es un secreto filtrado (A10)."
            )


# =====================================================================
# A11-a — endurecimiento del servicio `web`
# =====================================================================

@pytest.fixture(scope="module")
def web(services):
    svc = services.get("web")
    assert isinstance(svc, dict), "No hay servicio `web` en el compose base."
    return svc


def _command_text(service: dict) -> str:
    command = service.get("command")
    assert command is not None, "El servicio no declara `command`."
    if isinstance(command, str):
        return command
    return " ".join(map(str, command))


def test_a11a_web_gunicorn_tres_workers(web):
    text = _command_text(web)
    assert "gunicorn" in text, f"El command de `web` no lanza gunicorn: {text!r} (A11)."
    assert re.search(r"--workers\s+3", text), (
        f"El command de `web` no fija `--workers 3`: {text!r} (A11)."
    )


def test_a11a_web_sin_ports(web):
    assert "ports" not in web, (
        "El servicio `web` publica `ports` en el base; gunicorn sólo debe ser "
        "alcanzable por nginx (el override lo repone en dev a propósito) (A11)."
    )


def test_a11a_web_sin_bindmount_de_codigo(web):
    """
    Los `volumes` de `web` en el base NO incluyen el bind-mount de código
    `.:/usr/src/app`; sólo el de logs. Montar el código en producción permitiría
    servir un árbol modificado en caliente.
    """
    volumes = web.get("volumes") or []
    montajes = [str(v) for v in volumes]
    for m in montajes:
        destino = m.split(":")[1] if ":" in m else m
        assert destino.rstrip("/") != "/usr/src/app", (
            f"`web` monta el código en {m!r}; el base no debe traer el bind-mount de "
            "código (sólo el de logs). Eso vive en el override (A11)."
        )


def test_a11a_web_no_fija_debug(web):
    """
    El base no activa DEBUG en `web`: no trae `environment` con DJANGO_DEBUG ni
    DEBUG=1. La configuración llega por `env_file: .env`, y el DEBUG de desarrollo
    lo pone el override (trampa 12).
    """
    env_items = _env_items(web)
    for key, value in env_items:
        assert key not in ("DJANGO_DEBUG", "DEBUG"), (
            f"`web` fija {key}={value!r} en el base; DEBUG no debe activarse aquí, "
            "sólo en el override (A11)."
        )
