"""
L0 · Configuración de nginx  —  A12-a del inventario (§4.3 PLAN-DE-PRUEBAS.md)

Se lee `backend/infrastructure/nginx/nginx.conf` como **texto** (vía
`read_repo_text`); no se parsea la gramática de nginx ni se levanta nada. Las
aserciones son sobre directivas concretas del fichero de producción.

  A12-a:
    · `server_tokens off;`  (no anunciar la versión).
    · `limit_req_zone` con auth_zone a 5r/m y api_zone a 30r/s.
    · `limit_conn conn_zone 50;`
    · `client_max_body_size 110m;`
    · `listen 443 ssl;`
    · el server :80 redirige con `return 301 https...`.
    · SIN bloques `server` de MinIO.

Trampa 16 (variante): "minio" SÍ aparece en el fichero, pero en un COMENTARIO que
explica su retirada. Por eso NO se comprueba `"minio" not in conf`, sino la
AUSENCIA de directivas reales (`listen 9000/9001`, `proxy_pass` hacia minio).
"""

import re

import pytest

pytestmark = pytest.mark.l0

_NGINX_REL = "backend/infrastructure/nginx/nginx.conf"


@pytest.fixture(scope="module")
def conf(read_repo_text) -> str:
    return read_repo_text(_NGINX_REL)


def test_a12a_server_tokens_off(conf):
    assert re.search(r"server_tokens\s+off\s*;", conf), (
        "nginx no lleva `server_tokens off;`: anunciaría su versión en cabeceras y "
        "páginas de error (A12)."
    )


def test_a12a_auth_zone_5_por_minuto(conf):
    assert re.search(
        r"limit_req_zone\s+\S+\s+zone=auth_zone:\S+\s+rate=5r/m\s*;", conf
    ), "Falta la zona de rate limit auth_zone a 5r/m (login/registro) (A12)."


def test_a12a_api_zone_30_por_segundo(conf):
    assert re.search(
        r"limit_req_zone\s+\S+\s+zone=api_zone:\S+\s+rate=30r/s\s*;", conf
    ), "Falta la zona de rate limit api_zone a 30r/s (A12)."


def test_a12a_limit_conn_50(conf):
    assert re.search(r"limit_conn\s+conn_zone\s+50\s*;", conf), (
        "Falta `limit_conn conn_zone 50;`: sin cota de conexiones concurrentes por "
        "IP (A12)."
    )


def test_a12a_client_max_body_size_110m(conf):
    assert re.search(r"client_max_body_size\s+110m\s*;", conf), (
        "Falta `client_max_body_size 110m;`: nginx cortaría subidas legítimas antes "
        "de que Django emitiera su propio error (A12)."
    )


def test_a12a_listen_443_ssl(conf):
    assert re.search(r"listen\s+443\s+ssl\s*;", conf), (
        "No hay `listen 443 ssl;`: la aplicación no se sirve por TLS (A12)."
    )


def test_a12a_puerto_80_redirige_a_https(conf):
    assert re.search(r"return\s+301\s+https", conf), (
        "El server :80 no redirige con `return 301 https...`: habría contenido "
        "servido en texto plano (A12)."
    )


# =====================================================================
# A12-a — sin bloques server de MinIO (trampa: "minio" queda en un comentario)
# =====================================================================

def test_a12a_sin_listen_minio(conf):
    """No hay `listen 9000`/`listen 9001`: los server de MinIO se eliminaron."""
    assert not re.search(r"listen\s+9000\b", conf), (
        "Reaparece `listen 9000` (API de MinIO) en nginx: la consola/almacén no "
        "debe publicarse por el proxy (A12)."
    )
    assert not re.search(r"listen\s+9001\b", conf), (
        "Reaparece `listen 9001` (consola de MinIO) en nginx (A12)."
    )


def test_a12a_sin_proxy_pass_a_minio(conf):
    """
    Ningún `proxy_pass` apunta a minio. Se comprueba la directiva real, no la
    palabra "minio" (que sobrevive en el comentario que explica su retirada).
    """
    proxy_targets = re.findall(r"proxy_pass\s+([^;]+);", conf)
    ofensivos = [t.strip() for t in proxy_targets if "minio" in t.lower()]
    assert not ofensivos, (
        f"Hay proxy_pass hacia minio en nginx: {ofensivos}. El almacén de ficheros "
        "cifrados no debe ser alcanzable por el proxy (A12)."
    )
