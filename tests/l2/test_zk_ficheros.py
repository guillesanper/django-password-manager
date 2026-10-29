"""L2 · stack_prod · Ficheros zero-knowledge por HTTP real.

  - M2 ⭐  6 descargas del mismo objeto -> idéntico sha256, e idéntico al blob
    subido. Con zero-knowledge el servidor guarda un blob OPACO; esto prueba que
    MinIO devuelve bytes idénticos entre los 3 workers de gunicorn y que la capa
    SSE-S3 (ENCRYPTION_KEY de sistema) es estable. Sustituye al viejo smoke.py,
    adaptado al flujo de subida cifrada en cliente.
  - M4  la descarga es Content-Type: application/octet-stream + Content-Disposition
    attachment + X-Content-Type-Options: nosniff.

El servidor no cifra ni interpreta el blob (file_views.py): sube el contenido de
`file` tal cual a MinIO y lo devuelve tal cual. Por eso basta subir bytes opacos
aleatorios; no hace falta cifrar de verdad para ejercer la propiedad de M2/M4.
"""

import hashlib
import os
import uuid

import pytest

from _l2lib import csrf_headers

pytestmark = [pytest.mark.l2, pytest.mark.stack_prod]

_DESCARGAS = 6  # >= nº de workers (3), para cruzar workers en varias descargas


def _subir_blob(session, base_url, blob):
    """Sube un blob opaco por /api/files/upload/. Devuelve el id del fichero."""
    client_id = str(uuid.uuid4())
    r = session.post(
        base_url + "/api/files/upload/",
        files={"file": ("blob.bin", blob, "application/octet-stream")},
        data={"client_id": client_id, "ciphertext": "l2-opaque-metadata-blob"},
        headers=csrf_headers(session, base_url),
        timeout=30,
    )
    assert r.status_code == 200, f"upload falló ({r.status_code}): {r.text[:500]}"
    payload = r.json()
    assert payload.get("success") is True, f"upload sin success: {payload}"
    file_id = payload["file"]["id"]
    return file_id


def _descargar(session, base_url, file_id):
    """Descarga el blob por POST /api/files/<id>/download/. Devuelve la respuesta."""
    r = session.post(
        base_url + f"/api/files/{file_id}/download/",
        headers=csrf_headers(session, base_url),
        timeout=30,
    )
    return r


@pytest.fixture(scope="module")
def blob_subido(auth_session):
    """Sube un blob aleatorio una vez y lo borra al terminar el módulo."""
    session, base_url = auth_session
    blob = os.urandom(64 * 1024)  # 64 KiB opacos
    file_id = _subir_blob(session, base_url, blob)
    yield session, base_url, file_id, blob
    # Limpieza del fichero concreto (el borrado del usuario en el teardown de sesión
    # también lo arrastraría, pero se retira aquí para no dejar el objeto colgando).
    try:
        session.post(
            base_url + f"/api/files/{file_id}/delete/",
            headers=csrf_headers(session, base_url),
            timeout=30,
        )
    except Exception:
        pass


# --------------------------------------------------------------------------- #
# M2 ⭐ — 6 descargas idénticas y byte a byte iguales al blob subido.
# --------------------------------------------------------------------------- #
def test_m2_seis_descargas_mismo_sha256(blob_subido):
    session, base_url, file_id, blob = blob_subido
    sha_subido = hashlib.sha256(blob).hexdigest()

    hashes_descargados = []
    for i in range(_DESCARGAS):
        r = _descargar(session, base_url, file_id)
        assert r.status_code == 200, f"descarga {i} devolvió {r.status_code}: {r.text[:300]}"
        hashes_descargados.append(hashlib.sha256(r.content).hexdigest())

    unicos = set(hashes_descargados)
    assert len(unicos) == 1, (
        f"las {_DESCARGAS} descargas NO devolvieron bytes idénticos: {unicos}. "
        "Con 3 workers de gunicorn, esto delata que ENCRYPTION_KEY/SSE no es estable "
        "entre workers (M2)."
    )
    assert unicos.pop() == sha_subido, (
        "el sha256 descargado no coincide con el subido: el servidor está alterando "
        "el blob opaco (debería devolverlo byte a byte)."
    )


# --------------------------------------------------------------------------- #
# M4 — cabeceras de la descarga (octet-stream + attachment + nosniff).
# --------------------------------------------------------------------------- #
def test_m4_cabeceras_de_descarga(blob_subido):
    session, base_url, file_id, _blob = blob_subido
    r = _descargar(session, base_url, file_id)
    assert r.status_code == 200, f"descarga devolvió {r.status_code}"

    ct = r.headers.get("Content-Type", "")
    assert ct.split(";")[0].strip() == "application/octet-stream", (
        f"Content-Type inesperado: {ct!r} (M4 exige application/octet-stream)"
    )
    cd = r.headers.get("Content-Disposition", "")
    assert "attachment" in cd.lower(), (
        f"Content-Disposition sin 'attachment': {cd!r} (M4)"
    )
    nosniff = r.headers.get("X-Content-Type-Options", "")
    assert nosniff.lower() == "nosniff", (
        f"falta X-Content-Type-Options: nosniff (llegó {nosniff!r}, M4)"
    )
