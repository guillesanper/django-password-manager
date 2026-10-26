"""L1 — copia del bucket de ficheros (N18, AU-17).

`manage.py backup_minio <dir>` (servicio `maintenance`) baja a disco los objetos del bucket que
falten o hayan cambiado de tamaño, y `--restore` sube los que falten en el bucket. Se baja por
la API S3, así que el SSE-S3 de MinIO ya viene quitado: la copia no depende de
MINIO_KMS_SECRET_KEY. Lo que queda son los blobs cifrados en el navegador, que el servidor
nunca pudo leer.

Corre contra el MinIO de la pila (o `moto` en su lugar), en un bucket propio por test.
"""

import io
import uuid
from unittest import mock

import pytest
from django.core.management import CommandError, call_command

from myapp.minio_service import enhanced_minio_service

pytestmark = pytest.mark.l1

OBJETOS = {
    "user_7/a.bin": b"\x00blob-a" * 100,
    "user_7/sub/b.bin": b"\x01blob-b",
    "user_9/c.bin": b"",
}


@pytest.fixture
def bucket(monkeypatch):
    client = enhanced_minio_service.client
    nombre = f"test-n18-{uuid.uuid4().hex[:8]}"
    client.make_bucket(nombre)
    monkeypatch.setattr(enhanced_minio_service, "bucket_name", nombre)
    for clave, datos in OBJETOS.items():
        client.put_object(nombre, clave, io.BytesIO(datos), len(datos))
    yield nombre
    for obj in client.list_objects(nombre, recursive=True):
        client.remove_object(nombre, obj.object_name)
    client.remove_bucket(nombre)


def _leer(nombre, clave):
    resp = enhanced_minio_service.client.get_object(nombre, clave)
    try:
        return resp.read()
    finally:
        resp.close()
        resp.release_conn()


def test_n18_copia_todos_los_objetos(bucket, tmp_path):
    call_command("backup_minio", str(tmp_path))
    for clave, datos in OBJETOS.items():
        assert (tmp_path / clave).read_bytes() == datos
    assert not list(tmp_path.rglob("*.part"))


def test_n18_la_segunda_copia_solo_baja_lo_nuevo(bucket, tmp_path):
    call_command("backup_minio", str(tmp_path))
    enhanced_minio_service.client.put_object(bucket, "user_9/nuevo.bin", io.BytesIO(b"n"), 1)

    with mock.patch.object(enhanced_minio_service.client, "get_object",
                           wraps=enhanced_minio_service.client.get_object) as get:
        call_command("backup_minio", str(tmp_path))
    assert [c.args[1] for c in get.call_args_list] == ["user_9/nuevo.bin"]


def test_n18_no_borra_de_la_copia_lo_borrado_del_bucket(bucket, tmp_path):
    """Una copia que replicase los borrados no serviría para recuperar un borrado por error."""
    call_command("backup_minio", str(tmp_path))
    enhanced_minio_service.client.remove_object(bucket, "user_7/a.bin")
    call_command("backup_minio", str(tmp_path))
    assert (tmp_path / "user_7/a.bin").exists()


def test_n18_restaurar_sube_lo_que_falta(bucket, tmp_path):
    call_command("backup_minio", str(tmp_path))
    enhanced_minio_service.client.remove_object(bucket, "user_7/sub/b.bin")
    (tmp_path / "user_7/sub/b.bin.part").write_bytes(b"a medias")

    with mock.patch.object(enhanced_minio_service.client, "put_object",
                           wraps=enhanced_minio_service.client.put_object) as put:
        call_command("backup_minio", str(tmp_path), "--restore")

    assert [c.args[1] for c in put.call_args_list] == ["user_7/sub/b.bin"], (
        "sólo debe subir lo que falta, y nunca un .part"
    )
    assert put.call_args.kwargs.get("sse") is not None, "debe volver a cifrar at-rest con SSE-S3"
    assert _leer(bucket, "user_7/sub/b.bin") == OBJETOS["user_7/sub/b.bin"]


def test_n18_una_clave_no_sale_del_directorio(bucket, tmp_path):
    """minio-py no deja crear claves con `..`, pero S3 sí las admite: otro cliente podría
    haberlas escrito. Se simula en el listado."""
    falso = mock.Mock(object_name="../fuera.bin", size=1)
    destino = tmp_path / "copia"
    with mock.patch.object(enhanced_minio_service.client, "list_objects", return_value=[falso]), \
            pytest.raises(CommandError, match="fuera del directorio"):
        call_command("backup_minio", str(destino))
    assert not (tmp_path / "fuera.bin").exists()
