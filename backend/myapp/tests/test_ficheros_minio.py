"""L1 — MinIO no es una dependencia de arranque y los ficheros no pasan enteros por memoria (N12).

  - N12   `MinIOService()` se construía al importar las vistas y preguntaba a MinIO si existía
          el bucket, con los plazos de minio-py por defecto (5 min por operación de socket y
          5 reintentos con espera). Con MinIO caído, `migrate` no arrancaba, un worker
          reciclado se colgaba hasta el WORKER TIMEOUT y cada llamada esperaba ~6 s.
          `/api/files/` hacía un stat_object por fichero. Ahora construir el servicio no habla
          con MinIO, cada llamada tiene un plazo corto y listar sólo lee la BD.
          La subida leía el blob entero y la descarga lo copiaba en la respuesta (~2× su
          tamaño en RAM). Ahora se pasan a trozos.

Los tests de subida y descarga hablan con el MinIO de la pila (o `moto` en su lugar) sobre el
bucket de test. La memoria se mide con `tracemalloc`, que cuenta los `bytes` de Python: un blob
leído entero aparece en el pico; uno pasado a trozos, no.
"""

import hashlib
import io
import time
import tracemalloc
import uuid
from unittest import mock

import pytest
import urllib3
from django.core.files.uploadedfile import SimpleUploadedFile
from django.core.management import call_command
from django.test import Client, RequestFactory
from rest_framework_simplejwt.tokens import AccessToken

from myapp.minio_service import MinIOService, enhanced_minio_service
from myapp.models import EncryptedFile
from myapp.views.file_views import upload_file_combined

pytestmark = pytest.mark.l1

MIB = 1024 * 1024
# Bastante mayor que una parte de la subida multiparte (5 MiB), para que leerlo entero se note.
BLOB_SIZE = 32 * MIB
# Picos medidos: ~10 MiB al subir (una parte y la copia que hace minio-py al enviarla) y
# ~0,4 MiB al descargar. Leer el blob entero da al menos BLOB_SIZE.
PICO_MAXIMO_SUBIDA = BLOB_SIZE // 2
PICO_MAXIMO_DESCARGA = 2 * MIB


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


def _pico_de_memoria(funcion):
    tracemalloc.start()
    try:
        resultado = funcion()
        return resultado, tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()


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
# N12 — subida y descarga a trozos
# --------------------------------------------------------------------------- #
@pytest.mark.django_db
def test_n12_subida_guarda_el_tamano_sin_leer_el_blob_entero(zk_user, bucket):
    contenido = b"\x5a" * BLOB_SIZE
    # La petición se construye antes de medir: su cuerpo en memoria es cosa del test.
    request = RequestFactory().post(
        "/api/files/upload/",
        {
            "file": SimpleUploadedFile("blob.bin", contenido),
            "client_id": str(uuid.uuid4()),
            "ciphertext": "metadatos-opacos",
        },
        **_bearer(zk_user.user),
    )
    del contenido

    r, pico = _pico_de_memoria(lambda: upload_file_combined(request))

    assert r.status_code == 200, f"la subida respondió {r.status_code}: {r.content[:300]}"
    fichero = EncryptedFile.objects.get(user=zk_user.user)
    assert fichero.size == BLOB_SIZE
    assert enhanced_minio_service.get_file_info(fichero.file_path)["info"]["size"] == BLOB_SIZE
    assert pico < PICO_MAXIMO_SUBIDA, f"la subida llegó a {pico / MIB:.1f} MiB en memoria"


@pytest.mark.django_db
def test_n12_descarga_a_trozos_sin_leer_el_blob_entero(zk_user, bucket):
    contenido = bytes(range(256)) * (BLOB_SIZE // 256)
    esperado = hashlib.sha256(contenido).hexdigest()
    fichero = _registro(zk_user.user, size=BLOB_SIZE, file_path=_guardar_blob(zk_user.user, contenido))
    del contenido

    def descargar():
        r = Client(raise_request_exception=False).post(
            f"/api/files/{fichero.id}/download/", **_bearer(zk_user.user),
        )
        resumen, total = hashlib.sha256(), 0
        for trozo in r.streaming_content if r.streaming else [r.content]:
            resumen.update(trozo)
            total += len(trozo)
        return r, resumen.hexdigest(), total

    (r, recibido, total), pico = _pico_de_memoria(descargar)

    assert r.status_code == 200, f"la descarga respondió {r.status_code}"
    assert int(r["Content-Length"]) == total == BLOB_SIZE
    assert recibido == esperado, "el blob descargado no es el guardado"
    assert pico < PICO_MAXIMO_DESCARGA, f"la descarga llegó a {pico / MIB:.1f} MiB en memoria"


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
