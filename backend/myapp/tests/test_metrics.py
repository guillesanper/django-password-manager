"""L1 — /metrics sirve las métricas reales de django_prometheus (N6).

Antes `/metrics` lo atendía una vista hecha a mano (`metrics_view`) con dos
métricas: el número de usuarios y `django_db_connections`, que valía
`len(connection.queries)`, siempre 0 con DEBUG=False. django_prometheus estaba en
INSTALLED_APPS pero sin middleware, sin URL y sin el backend de BD instrumentado,
así que no medía nada.

Se comprueba por la cadena real (`Client`): que las métricas de petición existen
(middleware cableado) y que las de BD existen tras una consulta (backend
instrumentado).
"""

import pytest
from django.contrib.auth import get_user_model
from django.test import Client

pytestmark = pytest.mark.l1


@pytest.mark.django_db
def test_n6_metrics_de_django_prometheus():
    get_user_model().objects.count()

    r = Client().get("/metrics")

    assert r.status_code == 200
    assert r["Content-Type"].startswith("text/plain")
    body = r.content.decode()
    assert "django_http_requests_before_middlewares_total" in body, (
        "faltan las métricas de petición: PrometheusBefore/AfterMiddleware no están en MIDDLEWARE"
    )
    assert 'django_db_execute_total{alias="default",vendor="postgresql"}' in body, (
        "faltan las métricas de BD: el ENGINE no es el instrumentado de django_prometheus"
    )
    assert "django_users_total" not in body, "sigue respondiendo la vista hecha a mano"
