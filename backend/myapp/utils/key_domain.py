"""Dominio de clave de una bóveda (Fase 2, zero-knowledge).

Una entrada v2 está cifrada bajo la clave del dominio de su bóveda: la **VaultKey principal**
(bóvedas públicas o sin bóveda) o la **VaultSubKey** propia de una bóveda privada v2. Mover una
entrada entre dominios distintos exige re-cifrarla en el cliente: el servidor sólo ve blobs
opacos y guardar un ciphertext de un dominio bajo otro lo dejaría indescifrable.

Estas dos utilidades centralizan ese criterio para las vistas que mueven entradas
(`password_views` en move/batch-move y `vault_views` al borrar una bóveda con contenido).
"""

from django.http import JsonResponse


def is_private_v2(vault):
    """True si el vault usa su dominio de clave propio (VaultSubKey), no la VaultKey principal."""
    return vault is not None and vault.is_private and vault.vault_crypto_version >= 2


def reencrypt_required_response():
    """400 cuando un movimiento cambia de dominio de clave y falta el ciphertext re-cifrado.

    Se rechaza en voz alta (fail-closed) en vez de guardar un blob que la clave destino no
    descifra: la seguridad y la integridad se centralizan en el backend.
    """
    return JsonResponse({
        'success': False,
        'error': 'Mover contraseñas entre una bóveda privada y otro dominio exige re-cifrarlas.',
        'code': 'REENCRYPT_REQUIRED',
    }, status=400)
