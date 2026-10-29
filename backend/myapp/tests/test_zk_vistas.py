"""L1 — contrato de las vistas de contraseñas zero-knowledge.

Cada petición atraviesa la cadena REAL con `Client` y un JWT por Bearer, como en
`test_rate_limit.py`. El ciphertext es un blob opaco cualquiera: el servidor no lo abre,
así que lo que se fija aquí es qué guarda y qué rechaza.

  - N8  Editar exige el client_id de la entrada. Forma parte de la AAD del blob, así
        que es inmutable: con otro (o sin él) la vista responde 400 y no toca la fila.
        Antes lo ignoraba en silencio, y como el cliente re-cifraba con uno nuevo, la
        entrada editada dejaba de descifrarse.

La otra mitad de N8, que el cliente re-cifra con el client_id guardado, la cubre
`frontend/src/services/passwordService.test.ts` (L3).
"""

import uuid

import pytest
from django.test import Client
from rest_framework_simplejwt.tokens import AccessToken

from myapp.models import PasswordEntry

pytestmark = pytest.mark.l1


def _bearer(user):
    return f"Bearer {AccessToken.for_user(user)}"


@pytest.fixture
def entrada(zk_user):
    return PasswordEntry.objects.create(
        user=zk_user.user,
        client_id=uuid.uuid4(),
        ciphertext="blob-original",
        crypto_version=2,
    )


def _editar(user, entry_id, body):
    return Client(raise_request_exception=False).post(
        f"/api/passwords/{entry_id}/update/",
        data=body,
        content_type="application/json",
        HTTP_AUTHORIZATION=_bearer(user),
    )


# --------------------------------------------------------------------------- #
# N8 — editar exige el client_id de la entrada
# --------------------------------------------------------------------------- #
@pytest.mark.django_db
def test_n8_editar_con_su_client_id_sustituye_el_blob(zk_user, entrada):
    r = _editar(zk_user.user, entrada.id, {
        "client_id": str(entrada.client_id),
        "ciphertext": "blob-editado",
        "crypto_version": 2,
    })

    assert r.status_code == 200, r.content
    entrada.refresh_from_db()
    assert entrada.ciphertext == "blob-editado"


@pytest.mark.django_db
@pytest.mark.parametrize(
    ("client_id", "motivo"),
    [
        ("0b6e8f3c-5d1a-4c2e-9f7b-2a4d6c8e0f13", "otro client_id"),
        (None, "sin client_id"),
        ("no-es-un-uuid", "client_id no UUID"),
    ],
    ids=["otro", "ausente", "no-uuid"],
)
def test_n8_editar_sin_su_client_id_da_400_y_no_toca_la_entrada(
    zk_user, entrada, client_id, motivo
):
    body = {"ciphertext": "blob-editado", "crypto_version": 2}
    if client_id is not None:
        body["client_id"] = client_id

    r = _editar(zk_user.user, entrada.id, body)

    assert r.status_code == 400, f"{motivo}: {r.status_code} {r.content!r}"
    original_client_id = entrada.client_id
    entrada.refresh_from_db()
    assert entrada.ciphertext == "blob-original", (
        f"{motivo}: la vista sustituyó un blob que ya no se podría descifrar"
    )
    assert entrada.client_id == original_client_id


@pytest.mark.django_db
def test_n8_una_entrada_legacy_sin_client_id_no_se_edita(zk_user):
    legacy = PasswordEntry.objects.create(
        user=zk_user.user, client_id=None, ciphertext="blob-v1", crypto_version=1,
    )

    r = _editar(zk_user.user, legacy.id, {
        "client_id": str(uuid.uuid4()),
        "ciphertext": "blob-editado",
        "crypto_version": 2,
    })

    assert r.status_code == 400, r.content
    legacy.refresh_from_db()
    assert legacy.ciphertext == "blob-v1"
