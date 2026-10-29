"""L1 — batería G de modelos: alta, round-trip, __str__ y borrado en cascada.

Cubre G4 (§5): alta y round-trip de los 8 modelos (User + los 7 de myapp),
`__str__` no revienta en ninguno, y borrar un usuario arrastra en cascada
PasswordEntry, EncryptedFile, UserCrypto y Vault.

No es xfail: debe pasar hoy (§3).
"""

import uuid

import pytest

from myapp.models import (
    ActivityLog,
    EncryptedFile,
    PasswordEntry,
    SecurityEvent,
    UserCrypto,
    UserSettings,
    Vault,
)
from myapp.tests.conftest import TEST_MASTER_PASSWORD, build_user_crypto_material

pytestmark = [pytest.mark.l1, pytest.mark.django_db]


def _crear_grafo_de_usuario(django_user_model, sufijo=""):
    """Crea un usuario y una instancia de cada modelo de myapp enlazada a él."""
    user = django_user_model.objects.create_user(
        username=f"g4_user{sufijo}",
        email=f"g4_user{sufijo}@example.test",
        password="Wren$Kilo7pluto",
    )

    material = build_user_crypto_material(TEST_MASTER_PASSWORD)
    crypto = UserCrypto(
        user=user,
        kdf_salt=material["kdf_salt"],
        kdf_params=material["kdf_params"],
        wrapped_vault_key=material["wrapped_vault_key"],
        crypto_version=UserCrypto.CURRENT_CRYPTO_VERSION,
    )
    crypto.set_auth_key(material["auth_key_b64"])
    crypto.save()

    objetos = {
        "UserSettings": UserSettings.objects.create(user=user),
        "PasswordEntry": PasswordEntry.objects.create(
            user=user, ciphertext="blob", client_id=uuid.uuid4()
        ),
        "UserCrypto": crypto,
        "EncryptedFile": EncryptedFile.objects.create(
            user=user, ciphertext="blob", client_id=uuid.uuid4(), file_path="obj/x"
        ),
        "ActivityLog": ActivityLog.objects.create(
            user=user,
            activity_type="login",
            title="alta",
            description="round-trip",
            severity="info",
        ),
        "Vault": Vault.objects.create(user=user, name=f"vault{sufijo}"),
        "SecurityEvent": SecurityEvent.objects.create(
            user=user,
            event_type="failed_login",
            description="round-trip",
            ip_address="203.0.113.7",
        ),
    }
    return user, objetos


# --------------------------------------------------------------------------- #
# G4 — alta + round-trip + __str__ de los 8 modelos
# --------------------------------------------------------------------------- #
def test_g4_alta_round_trip_y_str(django_user_model):
    user, objetos = _crear_grafo_de_usuario(django_user_model)

    # Round-trip: cada objeto (incluido el User) tiene pk y se relee de la BD.
    todos = {"User": user, **objetos}
    for nombre, obj in todos.items():
        assert obj.pk is not None, f"{nombre} no recibió pk al guardarse."
        releido = type(obj).objects.get(pk=obj.pk)
        assert releido.pk == obj.pk, f"{nombre} no hace round-trip por la BD."
        # __str__ no debe reventar en ninguno.
        assert isinstance(str(releido), str) and str(releido), (
            f"{nombre}.__str__ devolvió algo vacío o lanzó."
        )


# --------------------------------------------------------------------------- #
# G4 — borrar el usuario arrastra en cascada el material del gestor
# --------------------------------------------------------------------------- #
def test_g4_borrado_usuario_cascada(django_user_model):
    user, _ = _crear_grafo_de_usuario(django_user_model, sufijo="_casc")
    user_id = user.id

    # Antes de borrar, todo existe.
    assert PasswordEntry.objects.filter(user_id=user_id).exists()
    assert EncryptedFile.objects.filter(user_id=user_id).exists()
    assert UserCrypto.objects.filter(user_id=user_id).exists()
    assert Vault.objects.filter(user_id=user_id).exists()

    user.delete()

    # El plan nombra estos cuatro explícitamente: no deben quedar huérfanos.
    assert not PasswordEntry.objects.filter(user_id=user_id).exists()
    assert not EncryptedFile.objects.filter(user_id=user_id).exists()
    assert not UserCrypto.objects.filter(user_id=user_id).exists()
    assert not Vault.objects.filter(user_id=user_id).exists()
