"""L1 — MinIO no es una dependencia de arranque ni de la lista de ficheros (N12).

  - N12   `MinIOService()` se construía al importar las vistas y preguntaba a MinIO si existía
          el bucket, con los plazos de minio-py por defecto (5 min por operación de socket y
          5 reintentos con espera). Con MinIO caído, `migrate` no arrancaba, un worker
          reciclado se colgaba hasta el WORKER TIMEOUT y cada llamada esperaba ~6 s.
          `/api/files/` hacía un stat_object por fichero. Ahora construir el servicio no habla
          con MinIO, cada llamada tiene un plazo corto y listar sólo lee la BD.

El test del relleno habla con el MinIO de la pila (o `moto` en su lugar) sobre el bucket de test.
"""

import io
import time
import uuid
from unittest import mock

import pytest
import urllib3
from django.core.management import call_command
from django.test import Client
from rest_framework_simplejwt.tokens import AccessToken

from myapp.minio_service import MinIOService, enhanced_minio_service
from myapp.models import EncryptedFile

pytestmark = pytest.mark.l1


@pytest.fixture
def bucket(zk_user):
    """Bucket de test creado y vaciado de los objetos del usuario al terminar."""
    client, nombre = enhanced_minio_service.client, enhanced_minio_service.bucket_name
    if not client.bucket_exists(nombre):
        client.make_bucket(nombre)
    yield
    enhanced_minio_service.delete_user_files(zk_user.user.id)


@pytest.fixture
def sin_red():
    """Cualquier petición HTTP del proceso falla y queda registrada."""
    with mock.patch.object(
        urllib3.PoolManager, "urlopen", side_effect=AssertionError("petición a MinIO"),
    ) as urlopen:
        yield urlopen


def _bearer(user):
    return {"HTTP_AUTHORIZATION": f"Bearer {AccessToken.for_user(user)}"}


def _registro(user, size=None, file_path=None):
    return EncryptedFile.objects.create(
        user=user,
        client_id=uuid.uuid4(),
        ciphertext="metadatos-opacos",
        crypto_version=2,
        file_path=file_path or f"user_{user.id}/{uuid.uuid4()}",
        size=size,
    )


def _guardar_blob(user, contenido):
    object_name = f"user_{user.id}/{uuid.uuid4()}"
    enhanced_minio_service.client.put_object(
        enhanced_minio_service.bucket_name, object_name, io.BytesIO(contenido), len(contenido),
    )
    return object_name


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


@pytest.mark.django_db
def test_n12_listar_ficheros_no_pregunta_a_minio(zk_user, sin_red):
    _registro(zk_user.user, size=1234)
    _registro(zk_user.user)  # subido antes de N12, sin tamaño todavía

    r = Client(raise_request_exception=False).get("/api/files/", **_bearer(zk_user.user))

    assert r.status_code == 200, f"/api/files/ respondió {r.status_code}: {r.content[:300]}"
    assert not sin_red.called, "/api/files/ hizo una petición a MinIO"
    con_tamano, sin_tamano = sorted(r.json()["files"], key=lambda f: "size" not in f)
    assert (con_tamano["size"], con_tamano["size_formatted"]) == (1234, "1.21 KB")
    assert "size" not in sin_tamano and "size_formatted" not in sin_tamano


# --------------------------------------------------------------------------- #
# N12 — relleno del tamaño de los ficheros anteriores
# --------------------------------------------------------------------------- #
@pytest.mark.django_db
def test_n12_backfill_rellena_el_tamano_sin_tocar_la_fecha(zk_user, bucket):
    antiguo = _registro(zk_user.user, file_path=_guardar_blob(zk_user.user, b"x" * 777))
    perdido = _registro(zk_user.user)  # su objeto ya no está en MinIO
    fecha = antiguo.updated_at

    call_command("backfill_file_sizes", stdout=io.StringIO())

    antiguo.refresh_from_db()
    perdido.refresh_from_db()
    assert antiguo.size == 777
    assert antiguo.updated_at == fecha, "rellenar el tamaño cambió la fecha del fichero"
    assert perdido.size is None
