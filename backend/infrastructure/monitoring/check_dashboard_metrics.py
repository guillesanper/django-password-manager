"""Comprueba contra Prometheus que el dashboard de Grafana no tiene paneles vacíos.

Extrae del JSON del dashboard todas las consultas PromQL y, de cada una, los
nombres de métrica. Falla (código 1) si alguna métrica no tiene ninguna serie en
Prometheus o si alguna consulta de panel no devuelve datos. Es la comprobación
que faltaba: el dashboard anterior consultaba métricas que no existían
(`django_db_connections_total`, `container_*`…) y nada lo avisaba, Grafana sólo
pintaba "No data".

Se ejecuta dentro de la red de la pila, porque Prometheus no publica puertos:

    docker compose exec web python infrastructure/monitoring/check_dashboard_metrics.py \
        --prometheus http://prometheus:9090

Lo llama también el test L2 tests/l2/test_observabilidad.py.
"""

import argparse
import json
import re
import sys
from pathlib import Path

import requests

DASHBOARD = Path(__file__).resolve().parent / "grafana" / "dashboards" / "backend-dashboard.json"

# Palabras de PromQL que tienen forma de nombre de métrica pero no lo son.
_KEYWORDS = {
    "by", "without", "on", "ignoring", "group_left", "group_right",
    "bool", "and", "or", "unless", "offset",
}
# El lookbehind evita leer como métrica la unidad de un número (`5m`, `1e3`).
_IDENT = re.compile(r"(?<![\w.])[a-zA-Z_:][a-zA-Z0-9_:]*")


def panel_queries(dashboard):
    """Devuelve `(título del panel, expresión)` para cada consulta del dashboard."""
    queries = []
    for panel in dashboard.get("panels", []):
        for target in panel.get("targets", []):
            if target.get("expr"):
                queries.append((panel.get("title", "?"), target["expr"]))
    return queries


def metric_names(expr):
    """Nombres de métrica de una expresión PromQL.

    Basta con un análisis léxico: se quitan las cadenas, los selectores de
    etiquetas, los rangos y las listas de `by (...)`, y de lo que queda, todo
    identificador que no sea una función (va seguido de `(`) ni una palabra
    reservada es una métrica.
    """
    expr = re.sub(r'"(?:[^"\\]|\\.)*"', "", expr)
    expr = re.sub(r"\{[^}]*\}", "", expr)
    expr = re.sub(r"\[[^\]]*\]", "", expr)
    expr = re.sub(
        r"\b(?:by|without|on|ignoring|group_left|group_right)\s*\([^)]*\)", "", expr
    )
    names = set()
    for match in _IDENT.finditer(expr):
        name = match.group()
        if name in _KEYWORDS or expr[match.end():].lstrip().startswith("("):
            continue
        names.add(name)
    return names


def _api(prometheus, path, params):
    response = requests.get(f"{prometheus}/api/v1/{path}", params=params, timeout=10)
    response.raise_for_status()
    return response.json()["data"]


def check(prometheus, dashboard):
    """Lista de problemas encontrados; vacía si todo panel tiene datos."""
    queries = panel_queries(dashboard)
    if not queries:
        # Típicamente el JSON viene envuelto en {"dashboard": …} (formato de la API
        # HTTP), que el provisioning de Grafana no carga.
        return ["el dashboard no tiene ninguna consulta en `panels`"]

    problems = []
    for name in sorted(set().union(*(metric_names(expr) for _, expr in queries))):
        if not _api(prometheus, "series", {"match[]": name}):
            problems.append(f"métrica sin series en Prometheus: {name}")

    for title, expr in queries:
        if not _api(prometheus, "query", {"query": expr})["result"]:
            problems.append(f"el panel '{title}' no devuelve datos: {expr}")

    return problems


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--prometheus", default="http://prometheus:9090")
    parser.add_argument("--dashboard", type=Path, default=DASHBOARD)
    args = parser.parse_args()

    dashboard = json.loads(args.dashboard.read_text(encoding="utf-8"))
    problems = check(args.prometheus.rstrip("/"), dashboard)

    for problem in problems:
        print(f"FALLO  {problem}")
    if problems:
        return 1
    print(f"OK  {len(panel_queries(dashboard))} consultas con datos en {args.prometheus}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
