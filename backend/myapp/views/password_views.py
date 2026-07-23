from rest_framework.decorators import api_view, permission_classes, authentication_classes
from rest_framework.permissions import IsAuthenticated
from ..authentication import CookieJWTAuthentication
from django.http import JsonResponse
from django.db import IntegrityError

import json
import uuid

from ..models import PasswordEntry, Vault
from ..utils.logging_utils import log_activity

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
    """Representación opaca de una entrada para el cliente."""
    return {
        'id': entry.id,
        'client_id': str(entry.client_id) if entry.client_id else None,
        'vault_id': entry.vault_id,
        'crypto_version': entry.crypto_version,
        'ciphertext': entry.ciphertext,
    }


@api_view(['GET'])
@authentication_classes([CookieJWTAuthentication])
@permission_classes([IsAuthenticated])
def api_accounts(request):
    """Devuelve todas las entradas del usuario como blobs opacos (A7 cerrado).

    El cliente descifra en local con la VaultKey y filtra/busca allí. Ya no se devuelven
    encrypted_password/encrypted_key/iv_or_nonce/salt: no queda material offline atacable.
    """
    accounts = PasswordEntry.objects.filter(user=request.user)
    data = [_serialize_entry(acc) for acc in accounts]
    return JsonResponse({'accounts': data})


@api_view(['POST'])
@authentication_classes([CookieJWTAuthentication])
@permission_classes([IsAuthenticated])
def add_password_with_vault_support(request):
    """Crea una entrada a partir del blob ya cifrado en cliente.

    Espera { client_id, ciphertext, crypto_version, vault_id?, vault_password? }.
    No recibe website/username/password en claro: van dentro de ciphertext.
    """
    try:
        data = json.loads(request.body)

        client_id = _valid_uuid(data.get('client_id'))
        ciphertext = data.get('ciphertext')

        if not client_id:
            return JsonResponse({'success': False, 'error': 'client_id (UUID) requerido'}, status=400)
        if not ciphertext:
            return JsonResponse({'success': False, 'error': 'ciphertext requerido'}, status=400)

        # Resolución del vault (la protección de bóveda privada se rehace en el paso 24).
        vault = None
        vault_id = data.get('vault_id')
        if vault_id:
            try:
                vault = Vault.objects.get(id=vault_id, user=request.user)
            except Vault.DoesNotExist:
                return JsonResponse({'success': False, 'error': 'Vault no encontrado'}, status=400)
            if vault.is_private:
                vault_password = (data.get('vault_password') or '').strip()
                if not vault.verify_vault_password(vault_password):
                    return JsonResponse({
                        'success': False,
                        'error': 'Contraseña del vault incorrecta',
                    }, status=400)

        try:
            password_entry = PasswordEntry.objects.create(
                user=request.user,
                vault=vault,
                client_id=client_id,
                ciphertext=ciphertext,
                crypto_version=int(data.get('crypto_version', 2)),
                # Columnas del esquema legado: vacías en v2 (el secreto está en ciphertext).
                website='',
                username='',
                encrypted_password='',
                encryption_algorithm='',
                iv_or_nonce='',
                encrypted_key='',
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
    """Entradas de un vault, como blobs opacos. El gate de posesión de bóveda privada (A9)
    se añade en el paso 24; de momento el contenido ya es opaco (cifrado bajo la VaultKey)."""
    try:
        try:
            vault = Vault.objects.get(id=vault_id, user=request.user)
        except Vault.DoesNotExist:
            return JsonResponse({'success': False, 'error': 'Vault no encontrado'}, status=404)

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
    """Mueve una entrada a otro vault (o la saca de todo vault). No toca el ciphertext."""
    try:
        data = json.loads(request.body)
        password_id = data.get('password_id')
        vault_id = data.get('vault_id')  # null = quitar de vault

        if not password_id:
            return JsonResponse({'success': False, 'error': 'ID de contraseña requerido'}, status=400)

        try:
            password_entry = PasswordEntry.objects.get(id=password_id, user=request.user)
        except PasswordEntry.DoesNotExist:
            return JsonResponse({'success': False, 'error': 'Contraseña no encontrada'}, status=404)

        destination_vault = None
        if vault_id:
            try:
                destination_vault = Vault.objects.get(id=vault_id, user=request.user)
            except Vault.DoesNotExist:
                return JsonResponse({'success': False, 'error': 'Vault destino no encontrado'}, status=404)
            if destination_vault.is_private:
                vault_password = (data.get('vault_password') or '').strip()
                if not destination_vault.verify_vault_password(vault_password):
                    return JsonResponse({
                        'success': False,
                        'error': 'Contraseña del vault incorrecta',
                    }, status=400)

        old_vault_name = password_entry.vault.name if password_entry.vault else 'Sin vault'
        password_entry.vault = destination_vault
        password_entry.save(update_fields=['vault', 'updated_at'])
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

        destination_vault = None
        if destination_vault_id:
            try:
                destination_vault = Vault.objects.get(id=destination_vault_id, user=request.user)
            except Vault.DoesNotExist:
                return JsonResponse({'success': False, 'error': 'Vault destino no encontrado'}, status=404)
            if destination_vault.is_private:
                vault_password = (data.get('vault_password') or '').strip()
                if not destination_vault.verify_vault_password(vault_password):
                    return JsonResponse({
                        'success': False,
                        'error': 'Contraseña del vault incorrecta',
                    }, status=400)

        moved_count = PasswordEntry.objects.filter(
            user=request.user, id__in=password_ids,
        ).update(vault=destination_vault)

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
