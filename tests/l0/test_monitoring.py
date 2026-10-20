"""
L0 · Observabilidad  —  N6 (§7·decies de AUDITORIA-SEGURIDAD.md)

Se leen como texto/YAML/JSON el dashboard de Grafana, su provisioning, el
`prometheus.yml`, el compose base y `nginx.conf`. No se levanta nada: lo que se
fija aquí es que la configuración PUEDE funcionar (Grafana carga el dashboard,
cada métrica tiene un exportador que Prometheus scrapea, /metrics no sale por
nginx). Que además haya datos lo comprueba L2 con
`check_dashboard_metrics.py` contra la pila.

La extracción de métricas es la del propio script, importado por ruta: la que se
prueba aquí es la misma que usa L2.
"""

import importlib.util
import json
import re

import pytest
import yaml

pytestmark = pytest.mark.l0

_MONITORING = "backend/infrastructure/monitoring"
_DASHBOARD_REL = f"{_MONITORING}/grafana/dashboards/backend-dashboard.json"

# Familia de métricas -> el target que la exporta. Una métrica cuya familia no
# está aquí no tiene exportador en la pila (era el caso de `container_*`, que
# exige cAdvisor).
_EXPORTADORES = {
    "django_": "web:8000",
    "pg_": "postgres-exporter:9187",
    "minio_": "minio:9000",
}


@pytest.fixture(scope="module")
def script(repo_path):
    path = repo_path(f"{_MONITORING}/check_dashboard_metrics.py")
    spec = importlib.util.spec_from_file_location("check_dashboard_metrics", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def dashboard(read_repo_text):
    return json.loads(read_repo_text(_DASHBOARD_REL))


@pytest.fixture(scope="module")
def compose(read_repo_text):
    return yaml.safe_load(read_repo_text("backend/docker-compose.yml"))


@pytest.fixture(scope="module")
def targets(read_repo_text):
    config = yaml.safe_load(read_repo_text(f"{_MONITORING}/prometheus/prometheus.yml"))
    return {
        target
        for job in config["scrape_configs"]
        for static in job.get("static_configs", [])
        for target in static["targets"]
    }


def test_n6_extraccion_de_metricas(script):
    expr = (
        'sum by (method, status) (rate(django_http_x_total{job="a", le="0.5"}[5m]))'
        " / ignoring(le) pg_up offset 5m"
    )
    assert script.metric_names(expr) == {"django_http_x_total", "pg_up"}


def test_n6_dashboard_en_formato_de_provisioning(dashboard, script):
    # El envoltorio {"dashboard": …} es el formato de la API HTTP: el provisioning
    # por ficheros no lo desenvuelve y el dashboard no se carga.
    assert "dashboard" not in dashboard, "el JSON viene envuelto en {'dashboard': …}"
    assert dashboard.get("uid") and dashboard.get("title")
    assert script.panel_queries(dashboard), "el dashboard no tiene consultas"


def test_n6_provider_apunta_al_directorio_montado(read_repo_text, compose):
    provisioning = yaml.safe_load(
        read_repo_text(f"{_MONITORING}/grafana/provisioning/dashboards/dashboard.yml")
    )
    path = provisioning["providers"][0]["options"]["path"]

    montajes = {
        volume.split(":")[1]: volume.split(":")[0]
        for volume in compose["services"]["grafana"]["volumes"]
    }
    assert montajes.get(path) == "./infrastructure/monitoring/grafana/dashboards", (
        f"el provider de Grafana lee {path}, pero los JSON del dashboard se montan en "
        f"{[c for c, h in montajes.items() if h.endswith('grafana/dashboards')]}"
    )


def test_n6_cada_metrica_tiene_exportador_scrapeado(dashboard, script, targets, compose):
    metricas = set().union(*(script.metric_names(e) for _, e in script.panel_queries(dashboard)))
    assert metricas

    servicios = set(compose["services"])
    for metrica in sorted(metricas):
        familia = next((f for f in _EXPORTADORES if metrica.startswith(f)), None)
        assert familia, f"{metrica}: ningún servicio de la pila exporta esta métrica"
        target = _EXPORTADORES[familia]
        assert target in targets, f"{metrica}: Prometheus no scrapea {target}"
        assert target.split(":")[0] in servicios, f"{metrica}: {target} no es un servicio"


def test_n6_prometheus_no_scrapea_postgres_directamente(targets):
    # Postgres no habla HTTP: su puerto como target está siempre caído.
    assert not [t for t in targets if t.endswith(":5432")]


def test_n6_metrics_no_sale_por_nginx(read_repo_text):
    nginx = read_repo_text("backend/infrastructure/nginx/nginx.conf")
    for ruta in ("/metrics", "/metrics/"):
        assert re.search(
            rf"location\s*=\s*{re.escape(ruta)}\s*\{{\s*return\s+404;", nginx
        ), f"nginx sirve {ruta} hacia fuera: las métricas son sólo para la red interna"
