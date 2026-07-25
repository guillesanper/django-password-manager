from rest_framework.decorators import api_view, permission_classes, authentication_classes
from rest_framework.permissions import IsAuthenticated
from ..authentication import CookieJWTAuthentication
from django.http import JsonResponse
from django.db import IntegrityError

import json
import uuid

from ..models import PasswordEntry, Vault
from ..utils.logging_utils import log_activity
from ..utils.cache_utils import CacheUnavailable, service_unavailable_response
from ..utils.vault_unlock import guard_private_vault_access, is_vault_unlocked
from ..utils.key_domain import (
    is_private_v2 as _is_private_v2,
    reencrypt_required_response as _reencrypt_required_response,
)

import logging

logger = logging.getLogger(__name__)


# ==========================================
# VISTAS DE CONTRASEÑAS (Fase 2, zero-knowledge)
# ==========================================
#
# El servidor sólo ve blobs opacos. Cada entrada v2 guarda:
#   - client_id (UUID, generado por el cliente, parte de la AAD)
#   - ciphertext (AES-256-GCM(VaultKey, {website, username, password, ...}))
#   - crypto_version = 2
# website/username/password viajan DENTRO del blob: el servidor nunca los ve. Por eso ya no hay
# cifrado ni descifrado aquí, ni se pide la contraseña maestra (no queda ningún oráculo, A3), ni
# los logs pueden nombrar el sitio (privacidad): se registran por id.


def _valid_uuid(value):
    """Normaliza a str-UUID canónico o devuelve None si no es un UUID válido."""
    if not value:
        return None
    try:
        return str(uuid.UUID(str(value)))
    except (ValueError, AttributeError, TypeError):
        return None


def _serialize_entry(entry):
    """Representación opaca de una entrada para el cliente.

    `created_at`/`updated_at` son metadatos no sensibles (cuándo se creó/actualizó la entrada, no
    su contenido) que el análisis de seguridad en cliente (paso 27) usa para la antigüedad.
    """
    return {
        'id': entry.id,
        'client_id': str(entry.client_id) if entry.client_id else None,
        'vault_id': entry.vault_id,
        'crypto_version': entry.crypto_version,
        'ciphertext': entry.ciphertext,
        'created_at': entry.created_at.isoformat(),
        'updated_at': entry.updated_at.isoformat(),
    }


@api_view(['GET'])
@authentication_classes([CookieJWTAuthentication])
@permission_classes([IsAuthenticated])
def api_accounts(request):
    """Devuelve todas las entradas del usuario como blobs opacos (A7 cerrado).

    El cliente descifra en local con la VaultKey y filtra/busca allí. Ya no se devuelven
    encrypted_password/encrypted_key/iv_or_nonce/salt: no queda material offline atacable.

    Las entradas de bóvedas privadas (v2) sólo se incluyen si la bóveda está desbloqueada en
    servidor (paso 24, A9): no se entrega ni el ciphertext de una bóveda cuya contraseña no se
    ha probado. Su contenido es opaco de todos modos (cifrado bajo la VaultSubKey).
    """
    # Bóvedas privadas zero-knowledge del usuario: se ocultan mientras estén bloqueadas.
    private_vault_ids = Vault.objects.filter(
        user=request.user, is_private=True, vault_crypto_version__gte=2,
    ).values_list('id', flat=True)

    locked_vault_ids = []
    try:
        for vid in private_vault_ids:
            if not is_vault_unlocked(request.user.id, vid):
                locked_vault_ids.append(vid)
    except CacheUnavailable:
        return service_unavailable_response()

    accounts = PasswordEntry.objects.filter(user=request.user)
    if locked_vault_ids:
        accounts = accounts.exclude(vault_id__in=locked_vault_ids)
    data = [_serialize_entry(acc) for acc in accounts]
    return JsonResponse({'accounts': data})


@api_view(['POST'])
@authentication_classes([CookieJWTAuthentication])
@permission_classes([IsAuthenticated])
def add_password_with_vault_support(request):
    """Crea una entrada a partir del blob ya cifrado en cliente.

    Espera { client_id, ciphertext, crypto_version, vault_id? }.
    No recibe website/username/password en claro: van dentro de ciphertext. Si el vault es
    privado, el ciphertext ya viene cifrado bajo su VaultSubKey (el cliente la tiene desbloqueada).
    """
    try:
        data = json.loads(request.body)

        client_id = _valid_uuid(data.get('client_id'))
        ciphertext = data.get('ciphertext')

        if not client_id:
            return JsonResponse({'success': False, 'error': 'client_id (UUID) requerido'}, status=400)
        if not ciphertext:
            return JsonResponse({'success': False, 'error': 'ciphertext requerido'}, status=400)

        # Resolución del vault. Para bóvedas privadas (v2) se exige desbloqueo probado en servidor
        # (paso 24, A9): sin él no se acepta contenido, y el flag de confianza del cliente ya no
        # existe. La contraseña del vault no viaja: el gate es el marcador de desbloqueo.
        vault = None
        vault_id = data.get('vault_id')
        if vault_id:
            try:
                vault = Vault.objects.get(id=vault_id, user=request.user)
            except Vault.DoesNotExist:
                return JsonResponse({'success': False, 'error': 'Vault no encontrado'}, status=400)
            denial = guard_private_vault_access(request.user, vault)
            if denial is not None:
                return denial

        try:
            password_entry = PasswordEntry.objects.create(
                user=request.user,
                vault=vault,
                client_id=client_id,
                ciphertext=ciphertext,
                crypto_version=int(data.get('crypto_version', 2)),
            )
        except IntegrityError:
            # client_id repetido (colisión o reintento): unique lo rechaza (anti-swap).
            return JsonResponse({'success': False, 'error': 'client_id duplicado'}, status=400)

        vault_info = f' en vault "{vault.name}"' if vault else ''
        log_activity(
            user=request.user,
            activity_type='password_created',
            title='Nueva contraseña creada',
            description=f'Contraseña creada (id {password_entry.id}){vault_info}',
            severity='success',
            related_obj=password_entry,
        )

        return JsonResponse({
            'success': True,
            'message': 'Contraseña creada exitosamente',
            'password_id': password_entry.id,
            'client_id': str(password_entry.client_id),
            'vault': vault.name if vault else None,
        })

    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'error': 'Datos JSON inválidos'}, status=400)
    except Exception:
        logger.exception("Error creating password")
        return JsonResponse({'success': False, 'error': 'Error interno del servidor'}, status=500)


@api_view(['POST'])
@authentication_classes([CookieJWTAuthentication])
@permission_classes([IsAuthenticated])
def update_password(request, pk):
    """Actualiza el blob de una entrada. El cliente re-cifra {website, username, password, ...}
    y envía el ciphertext nuevo. Sin contraseña maestra: no hay cripto en servidor."""
    try:
        data = json.loads(request.body)
        ciphertext = data.get('ciphertext')

        if not ciphertext:
            return JsonResponse({'success': False, 'error': 'ciphertext requerido'}, status=400)

        try:
            password_entry = PasswordEntry.objects.get(id=pk, user=request.user)
        except PasswordEntry.DoesNotExist:
            return JsonResponse({'success': False, 'error': 'Contraseña no encontrada'}, status=404)

        password_entry.ciphertext = ciphertext
        password_entry.crypto_version = int(data.get('crypto_version', password_entry.crypto_version or 2))
        password_entry.save(update_fields=['ciphertext', 'crypto_version', 'updated_at'])

        log_activity(
            user=request.user,
            activity_type='password_updated',
            title='Contraseña actualizada',
            description=f'Contraseña actualizada (id {password_entry.id})',
            severity='success',
        )

        return JsonResponse({'success': True, 'message': 'Contraseña actualizada exitosamente'})

    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'error': 'Datos JSON inválidos'}, status=400)
    except Exception:
        logger.exception("Error updating password")
        return JsonResponse({'success': False, 'error': 'Error interno del servidor'}, status=500)


@api_view(['POST'])
@authentication_classes([CookieJWTAuthentication])
@permission_classes([IsAuthenticated])
def delete_password(request, password_id):
    """Elimina una entrada. Autorizado por la sesión; sin contraseña maestra (ya no es un
    oráculo de descifrado). La confirmación de la maestra, si se quiere, es en el cliente."""
    try:
        try:
            password_entry = PasswordEntry.objects.get(id=password_id, user=request.user)
        except PasswordEntry.DoesNotExist:
            return JsonResponse({'success': False, 'error': 'Contraseña no encontrada'}, status=404)

        password_entry.delete()

        log_activity(
            user=request.user,
            activity_type='password_deleted',
            title='Contraseña eliminada',
            description=f'Contraseña eliminada (id {password_id})',
            severity='warning',
        )

        return JsonResponse({'success': True, 'message': 'Contraseña eliminada exitosamente'})

    except Exception:
        logger.exception("Error deleting password")
        return JsonResponse({'success': False, 'error': 'Error interno del servidor'}, status=500)


@api_view(['GET'])
@authentication_classes([CookieJWTAuthentication])
@permission_classes([IsAuthenticated])
def api_vault_passwords(request, vault_id):
    """Entradas de un vault, como blobs opacos. Si el vault es privado (v2), exige desbloqueo
    probado en servidor (paso 24, A9): deniega el contenido hasta probar posesión de la subclave."""
    try:
        try:
            vault = Vault.objects.get(id=vault_id, user=request.user)
        except Vault.DoesNotExist:
            return JsonResponse({'success': False, 'error': 'Vault no encontrado'}, status=404)

        denial = guard_private_vault_access(request.user, vault)
        if denial is not None:
            return denial

        passwords = PasswordEntry.objects.filter(user=request.user, vault=vault)
        passwords_data = [_serialize_entry(pwd) for pwd in passwords]

        return JsonResponse({
            'success': True,
            'vault': {
                'id': vault.id,
                'name': vault.name,
                'description': vault.description,
                'color': vault.color,
                'is_private': vault.is_private,
            },
            'passwords': passwords_data,
            'count': len(passwords_data),
        })

    except Exception:
        logger.exception("Error en api_vault_passwords")
        return JsonResponse({
            'success': False,
            'error': 'Error obteniendo contraseñas del vault',
        }, status=500)


@api_view(['GET'])
@authentication_classes([CookieJWTAuthentication])
@permission_classes([IsAuthenticated])
def api_unvaulted_passwords(request):
    """Entradas que no están en ningún vault, como blobs opacos."""
    try:
        passwords = PasswordEntry.objects.filter(user=request.user, vault__isnull=True)
        passwords_data = [_serialize_entry(pwd) for pwd in passwords]

        return JsonResponse({
            'success': True,
            'passwords': passwords_data,
            'count': len(passwords_data),
        })

    except Exception:
        logger.exception("Error en api_unvaulted_passwords")
        return JsonResponse({
            'success': False,
            'error': 'Error obteniendo contraseñas sin vault',
        }, status=500)


@api_view(['POST'])
@authentication_classes([CookieJWTAuthentication])
@permission_classes([IsAuthenticated])
def api_move_password_to_vault(request):
    """Mueve una entrada a otro vault (o la saca de todo vault).

    Mover a/desde una bóveda privada cambia de dominio de clave (VaultKey ↔ VaultSubKey), así que
    el cliente re-cifra la entrada y envía el `ciphertext` nuevo; en un movimiento del mismo
    dominio (público↔público↔sin vault) no hace falta. Ambas bóvedas privadas implicadas deben
    estar desbloqueadas en servidor (paso 24, A9)."""
    try:
        data = json.loads(request.body)
        password_id = data.get('password_id')
        vault_id = data.get('vault_id')  # null = quitar de vault
        new_ciphertext = data.get('ciphertext')  # presente sólo si cambia el dominio de clave

        if not password_id:
            return JsonResponse({'success': False, 'error': 'ID de contraseña requerido'}, status=400)

        try:
            password_entry = PasswordEntry.objects.get(id=password_id, user=request.user)
        except PasswordEntry.DoesNotExist:
            return JsonResponse({'success': False, 'error': 'Contraseña no encontrada'}, status=404)

        # Gate de la bóveda ORIGEN: si la entrada vive en una privada, hay que tenerla desbloqueada
        # (el cliente la necesita abierta para re-cifrar al sacarla).
        if password_entry.vault_id:
            denial = guard_private_vault_access(request.user, password_entry.vault)
            if denial is not None:
                return denial

        destination_vault = None
        if vault_id:
            try:
                destination_vault = Vault.objects.get(id=vault_id, user=request.user)
            except Vault.DoesNotExist:
                return JsonResponse({'success': False, 'error': 'Vault destino no encontrado'}, status=404)
            denial = guard_private_vault_access(request.user, destination_vault)
            if denial is not None:
                return denial

        # Si cambia el dominio de clave (entra o sale de una bóveda privada v2), el cliente debe
        # aportar el blob re-cifrado; sin él se rechaza para no corromper la entrada (24b).
        dest_id = destination_vault.id if destination_vault else None
        if password_entry.vault_id != dest_id and (
            _is_private_v2(password_entry.vault) or _is_private_v2(destination_vault)
        ) and not new_ciphertext:
            return _reencrypt_required_response()

        old_vault_name = password_entry.vault.name if password_entry.vault else 'Sin vault'
        password_entry.vault = destination_vault
        update_fields = ['vault', 'updated_at']
        if new_ciphertext:
            password_entry.ciphertext = new_ciphertext
            update_fields.append('ciphertext')
        password_entry.save(update_fields=update_fields)
        new_vault_name = destination_vault.name if destination_vault else 'Sin vault'

        log_activity(
            user=request.user,
            activity_type='password_moved',
            title='Contraseña movida entre vaults',
            description=f'Contraseña (id {password_entry.id}) movida de "{old_vault_name}" a "{new_vault_name}"',
            severity='info',
        )

        return JsonResponse({
            'success': True,
            'message': f'Contraseña movida a "{new_vault_name}" exitosamente',
            'moved_from': old_vault_name,
            'moved_to': new_vault_name,
        })

    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'error': 'Datos JSON inválidos'}, status=400)
    except Exception:
        logger.exception("Error moviendo contraseña")
        return JsonResponse({'success': False, 'error': 'Error interno del servidor'}, status=500)


@api_view(['POST'])
@authentication_classes([CookieJWTAuthentication])
@permission_classes([IsAuthenticated])
def api_batch_delete_passwords(request):
    """Elimina varias entradas. Autorizado por la sesión; sin contraseña maestra."""
    try:
        data = json.loads(request.body)
        password_ids = data.get('password_ids', [])

        if not password_ids:
            return JsonResponse({'success': False, 'error': 'Lista de IDs de contraseñas requerida'}, status=400)

        deleted = PasswordEntry.objects.filter(user=request.user, id__in=password_ids).delete()
        deleted_count = deleted[0]

        if deleted_count:
            log_activity(
                user=request.user,
                activity_type='batch_password_deleted',
                title='Contraseñas eliminadas en lote',
                description=f'{deleted_count} contraseñas eliminadas',
                severity='warning',
            )

        return JsonResponse({
            'success': True,
            'message': f'{deleted_count} contraseñas eliminadas exitosamente',
            'deleted_count': deleted_count,
        })

    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'error': 'Datos JSON inválidos'}, status=400)
    except Exception:
        logger.exception("Error en batch delete")
        return JsonResponse({'success': False, 'error': 'Error interno del servidor'}, status=500)


@api_view(['POST'])
@authentication_classes([CookieJWTAuthentication])
@permission_classes([IsAuthenticated])
def api_batch_move_passwords(request):
    """Mueve varias entradas a un vault (o las saca de todo vault)."""
    try:
        data = json.loads(request.body)
        password_ids = data.get('password_ids', [])
        destination_vault_id = data.get('destination_vault_id')  # null = sin vault

        if not password_ids:
            return JsonResponse({'success': False, 'error': 'Lista de IDs de contraseñas requerida'}, status=400)

        # Re-cifrados por entrada para los movimientos que cambian de dominio de clave: mapa
        # { str(id): ciphertext }. Las entradas ausentes conservan su blob (mismo dominio).
        ciphertexts = data.get('ciphertexts') or {}
        if not isinstance(ciphertexts, dict):
            return JsonResponse({'success': False, 'error': 'ciphertexts debe ser un objeto'}, status=400)

        destination_vault = None
        if destination_vault_id:
            try:
                destination_vault = Vault.objects.get(id=destination_vault_id, user=request.user)
            except Vault.DoesNotExist:
                return JsonResponse({'success': False, 'error': 'Vault destino no encontrado'}, status=404)
            denial = guard_private_vault_access(request.user, destination_vault)
            if denial is not None:
                return denial

        entries = list(
            PasswordEntry.objects.filter(user=request.user, id__in=password_ids).select_related('vault')
        )

        # Gate de cada bóveda ORIGEN privada implicada (una comprobación por bóveda distinta).
        seen_source_vaults = set()
        for entry in entries:
            if entry.vault_id and entry.vault_id not in seen_source_vaults:
                seen_source_vaults.add(entry.vault_id)
                denial = guard_private_vault_access(request.user, entry.vault)
                if denial is not None:
                    return denial

        # Validación previa (antes de mutar nada): ninguna entrada puede cambiar de dominio de
        # clave sin su blob re-cifrado. Se comprueba entera para no dejar el lote a medias.
        dest_priv = _is_private_v2(destination_vault)
        dest_id = destination_vault.id if destination_vault else None
        for entry in entries:
            if entry.vault_id != dest_id and (_is_private_v2(entry.vault) or dest_priv) \
                    and not ciphertexts.get(str(entry.id)):
                return _reencrypt_required_response()

        moved_count = 0
        for entry in entries:
            entry.vault = destination_vault
            update_fields = ['vault', 'updated_at']
            new_ct = ciphertexts.get(str(entry.id))
            if new_ct:
                entry.ciphertext = new_ct
                update_fields.append('ciphertext')
            entry.save(update_fields=update_fields)
            moved_count += 1

        if moved_count:
            new_vault_name = destination_vault.name if destination_vault else 'Sin vault'
            log_activity(
                user=request.user,
                activity_type='batch_password_moved',
                title='Contraseñas movidas en lote',
                description=f'{moved_count} contraseñas movidas a "{new_vault_name}"',
                severity='info',
            )

        return JsonResponse({
            'success': True,
            'message': f'{moved_count} contraseñas movidas exitosamente',
            'moved_count': moved_count,
        })

    except json.JSONDecodeError:
        return JsonResponse({'success': False, 'error': 'Datos JSON inválidos'}, status=400)
    except Exception:
        logger.exception("Error en batch move")
        return JsonResponse({'success': False, 'error': 'Error interno del servidor'}, status=500)
