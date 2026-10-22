"""L1 — MinIO no es una dependencia de arranque (N12).

  - N12   `MinIOService()` se construía al importar las vistas y preguntaba a MinIO si existía
          el bucket, con los plazos de minio-py por defecto (5 min por operación de socket y
          5 reintentos con espera). Con MinIO caído, `migrate` no arrancaba, un worker
          reciclado se colgaba hasta el WORKER TIMEOUT y cada llamada esperaba ~6 s.
          Ahora construir el servicio no habla con MinIO y cada llamada tiene un plazo corto.
"""

import time
from unittest import mock

import pytest
import urllib3

from myapp.minio_service import MinIOService

pytestmark = pytest.mark.l1


@pytest.fixture
def sin_red():
    """Cualquier petición HTTP del proceso falla y queda registrada."""
    with mock.patch.object(
        urllib3.PoolManager, "urlopen", side_effect=AssertionError("petición a MinIO"),
    ) as urlopen:
        yield urlopen


# --------------------------------------------------------------------------- #
# N12 — MinIO caído no bloquea el arranque ni las peticiones
# --------------------------------------------------------------------------- #
def test_n12_construir_el_servicio_no_habla_con_minio(sin_red):
    # Es lo que pasa al importar las vistas: el URLconf, `migrate` y cada worker nuevo.
    MinIOService()
    assert not sin_red.called, "construir MinIOService hizo una petición a MinIO"


def test_n12_minio_que_rechaza_conexiones_falla_en_menos_de_un_segundo(settings):
    settings.MINIO_ENDPOINT = "127.0.0.1:1"  # nadie escucha: conexión rechazada al momento

    inicio = time.monotonic()
    resultado = MinIOService().get_file_info("user_0/inexistente")
    duracion = time.monotonic() - inicio

    assert not resultado["success"]
    assert duracion < 1, f"con MinIO caído la llamada tardó {duracion:.1f} s"
