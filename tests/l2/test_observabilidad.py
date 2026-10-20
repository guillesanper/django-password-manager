"""L2 · stack_prod · Observabilidad (N6).

  - El dashboard de Grafana no tiene paneles vacíos: `check_dashboard_metrics.py`
    se ejecuta dentro de `web` (Prometheus no publica puertos) y comprueba que
    cada métrica tiene series y cada consulta de panel devuelve datos.
  - /metrics no sale por nginx: las métricas son sólo para la red interna.

⚠️ Con la pila recién levantada, Prometheus necesita un par de scrapes (30 s cada
uno) antes de que `rate(...[5m])` devuelva algo: si falla justo tras el `up`,
espera un minuto y repite.
"""

import pytest

from _l2lib import BASE_URL_PROD, compose_run, container_output

pytestmark = [pytest.mark.l2, pytest.mark.stack_prod]

_SCRIPT = "infrastructure/monitoring/check_dashboard_metrics.py"


def test_n6_dashboard_sin_paneles_vacios(compose_cmd, backend_dir):
    res = compose_run(
        compose_cmd, backend_dir,
        ["exec", "-T", "web", "python", _SCRIPT, "--prometheus", "http://prometheus:9090"],
    )
    assert res.returncode == 0, f"el dashboard tiene paneles sin datos:\n{container_output(res)}"


@pytest.mark.parametrize("ruta", ["/metrics", "/metrics/"])
def test_n6_metrics_no_sale_por_nginx(http, ruta):
    r = http.get(BASE_URL_PROD + ruta, timeout=15, allow_redirects=False)
    assert r.status_code == 404, f"{ruta} responde {r.status_code} desde fuera"
