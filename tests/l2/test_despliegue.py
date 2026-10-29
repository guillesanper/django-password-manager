"""L2 · stack_prod · Despliegue: logs sin fugas, puertos cerrados, workers.

  - C4-b  `logs web` sin `Derived Key` ni `Generated new system encryption key`.
  - A10-b puertos internos cerrados (sólo nginx publica 80/443).
  - A11-b `logs web`: gunicorn maestro + 3 workers.

stack_prod NUNCA se había levantado (§1): esta es la primera vez que se ejerce
gunicorn ×3 y la superficie de red endurecida del compose base.
"""

import pytest

from _l2lib import container_web_logs, port_open

pytestmark = [pytest.mark.l2, pytest.mark.stack_prod]


# --------------------------------------------------------------------------- #
# C4-b — los logs del arranque no filtran material de clave (M1/C4).
# --------------------------------------------------------------------------- #
def test_c4b_logs_web_sin_material_de_clave(compose_cmd, backend_dir):
    logs = container_web_logs(compose_cmd, backend_dir)
    assert logs.strip(), "no se obtuvieron logs del servicio `web`"

    prohibidos = ["Derived Key", "Generated new system encryption key"]
    encontrados = [needle for needle in prohibidos if needle in logs]
    assert not encontrados, (
        f"los logs de `web` filtran material sensible: {encontrados}. "
        "C4/M1 exige que ninguna clave derivada ni de sistema se escriba en claro."
    )


# --------------------------------------------------------------------------- #
# A10-b — la red endurecida: sólo nginx (80/443) publica hacia el host.
# --------------------------------------------------------------------------- #
# Con el override (stack_dev) estos puertos SÍ están abiertos a propósito, por eso
# el test es stack_prod y se salta en dev (marca + hook del conftest).
_PUERTOS_QUE_DEBEN_ESTAR_CERRADOS = {
    5432: "PostgreSQL",
    6379: "Redis",
    9000: "MinIO API (S3)",
    9001: "MinIO consola",
    3000: "Grafana",
    9090: "Prometheus",
    8080: "webhook-collector",
}


@pytest.mark.parametrize(
    "puerto,servicio", sorted(_PUERTOS_QUE_DEBEN_ESTAR_CERRADOS.items())
)
def test_a10b_puertos_internos_cerrados(puerto, servicio):
    assert not port_open(puerto), (
        f"el puerto {puerto} ({servicio}) está publicado en stack_prod. "
        "El compose base sólo debe exponer nginx (80/443); si esto abre, hay un "
        "override aplicado o un `ports:` que no debería estar."
    )


# --------------------------------------------------------------------------- #
# A11-b — gunicorn con 3 workers (no runserver).
# --------------------------------------------------------------------------- #
def test_a11b_gunicorn_tres_workers(compose_cmd, backend_dir):
    logs = container_web_logs(compose_cmd, backend_dir)
    assert logs.strip(), "no se obtuvieron logs del servicio `web`"

    starting = logs.count("Starting gunicorn")
    booting = logs.count("Booting worker")

    # Un único proceso maestro de gunicorn.
    assert starting >= 1, (
        "no aparece 'Starting gunicorn' en los logs de `web`: ¿stack_prod está "
        "corriendo runserver en vez de gunicorn?"
    )
    assert starting == 1, (
        f"aparece 'Starting gunicorn' {starting} veces; se esperaba 1 maestro. "
        "¿La pila se reinició durante la corrida?"
    )
    # 3 workers arrancados. Se usa '>= 3' y no '== 3' porque
    # --max-requests/--max-requests-jitter recicla workers tras ~1000 peticiones,
    # y cada reemplazo registra otro 'Booting worker'. En una pila recién
    # levantada son exactamente 3; el >= evita un rojo espurio si ya sirvió mucho.
    assert booting >= 3, (
        f"'Booting worker' aparece {booting} veces; se esperaban al menos 3 "
        "(--workers 3). Menos de 3 significa que no hay tres workers."
    )
