from django.http import JsonResponse
from rest_framework.decorators import api_view, permission_classes,authentication_classes
from ..authentication import CookieJWTAuthentication
from rest_framework.permissions import IsAuthenticated
from django.utils import timezone
from django.db import transaction

import json

from ..models import Vault, PasswordEntry, UserCrypto
from ..utils.logging_utils import log_activity
from ..utils.master_key_guard import guard_auth_key, guard_vault_auth_key
from ..utils.cache_utils import CacheUnavailable, service_unavailable_response
from ..utils.vault_unlock import mark_vault_unlocked, clear_vault_unlock, guard_private_vault_access
from ..utils.key_domain import is_private_v2, reencrypt_required_response

import logging

logger = logging.getLogger(__name__)



@api_view(['GET'])
@authentication_classes([CookieJWTAuthentication])
@permission_classes([IsAuthenticated])
def api_vaults(request):
    """API para obtener todos los vaults del usuario"""
    try:
        vaults = Vault.objects.filter(user=request.user)
        
        vaults_data = []
        for vault in vaults:
            vault_data = {
                'id': vault.id,
                'name': vault.name,
                'description': vault.description,
                'color': vault.color,
                'is_private': vault.is_private,
                'password_count': vault.get_password_count(),
                'created_at': vault.created_at.isoformat(),
                'updated_at': vault.updated_at.isoformat()
            }
            vaults_data.append(vault_data)
        
        # Agregar información de contraseñas sin vault
        unvaulted_count = PasswordEntry.objects.filter(user=request.user, vault__isnull=True).count()
        
        return JsonResponse({
            'success': True,
            'vaults': vaults_data,
            'unvaulted_passwords': unvaulted_count
        })
        
    except Exception:
        logger.exception("Error en api_vaults")
        return JsonResponse({
            'success': False,
            'error': 'Error obteniendo vaults'
        }, status=500)


@api_view(['POST'])
@authentication_classes([CookieJWTAuthentication])
@permission_classes([IsAuthenticated])
def api_create_vault(request):
    """API para crear un nuevo vault"""
    try:
        data = json.loads(request.body)
        name = data.get('name', '').strip()
        description = data.get('description', '').strip()
        color = data.get('color', 'blue')
        is_private = data.get('is_private', False)

        # Validaciones
        if not name:
            return JsonResponse({
                'success': False,
                'error': 'El nombre del vault es requerido'
            }, status=400)
        
        if len(name) > 100:
            return JsonResponse({
                'success': False,
                'error': 'El nombre del vault no puede exceder 100 caracteres'
            }, status=400)
        
        # Verificar que no existe otro vault con el mismo nombre
        if Vault.objects.filter(user=request.user, name=name).exists():
            return JsonResponse({
                'success': False,
                'error': 'Ya tienes un vault con ese nombre'
            }, status=400)
        
        # Validar color
        valid_colors = [choice[0] for choice in Vault.VAULT_COLORS]
        if color not in valid_colors:
            return JsonResponse({
                'success': False,
                'error': 'Color de vault inválido'
            }, status=400)
        
        # Para bóvedas privadas, el cliente deriva la subclave con la contraseña del vault y envía
        # SÓLO material opaco (zero-knowledge, §8): el servidor nunca ve esa contraseña.
        sub_material = None
        if is_private:
            sub_kdf_salt = data.get('sub_kdf_salt')
            sub_auth_key = data.get('sub_auth_key')
            wrapped_vault_subkey = data.get('wrapped_vault_subkey')
            sub_kdf_params = data.get('sub_kdf_params') or {}
            if not all([sub_kdf_salt, sub_auth_key, wrapped_vault_subkey]):
                return JsonResponse({
                    'success': False,
                    'error': 'Falta el material criptográfico de la bóveda privada',
                }, status=400)
            if not isinstance(sub_kdf_params, dict):
                return JsonResponse({
                    'success': False,
                    'error': 'sub_kdf_params debe ser un objeto',
                }, status=400)
            sub_material = {
                'sub_kdf_salt': sub_kdf_salt,
                'sub_kdf_params': sub_kdf_params,
                'sub_auth_key': sub_auth_key,
                'wrapped_vault_subkey': wrapped_vault_subkey,
            }

        # Crear el vault
        vault = Vault.objects.create(
            user=request.user,
            name=name,
            description=description,
            color=color,
            is_private=is_private
        )

        # Guardar el material de subclave si es privado (zero-knowledge v2)
        if sub_material:
            vault.sub_kdf_salt = sub_material['sub_kdf_salt']
            vault.sub_kdf_params = sub_material['sub_kdf_params']
            vault.wrapped_vault_subkey = sub_material['wrapped_vault_subkey']
            vault.vault_crypto_version = 2
            vault.set_sub_auth_key(sub_material['sub_auth_key'])
            vault.save()
            # Quien acaba de crearla ya posee su subclave: se deja desbloqueada (marcador con TTL)
            # para poder usarla de inmediato sin un segundo viaje de desbloqueo. Best-effort: si
            # la caché no responde, el usuario simplemente tendrá que desbloquearla al usarla.
            try:
                mark_vault_unlocked(request.user.id, vault.id)
            except CacheUnavailable:
                logger.warning("No se pudo marcar la bóveda %s como desbloqueada al crearla", vault.id)
        
        # Log de actividad
        log_activity(
            user=request.user,
            activity_type='vault_created',
            title='Vault creado',
            description=f'Vault "{name}" {"(privado)" if is_private else "(público)"} creado',
            severity='success',
            related_obj=vault
        )
        
        return JsonResponse({
            'success': True,
            'message': 'Vault creado exitosamente',
            'vault': {
                'id': vault.id,
                'name': vault.name,
                'description': vault.description,
                'color': vault.color,
                'is_private': vault.is_private,
                'password_count': 0,
                'created_at': vault.created_at.isoformat()
            }
        })
        
    except json.JSONDecodeError:
        return JsonResponse({
            'success': False,
            'error': 'Datos JSON inválidos'
        }, status=400)
    except Exception:
        logger.exception("Error creando vault")
        return JsonResponse({
            'success': False,
            'error': 'Error interno del servidor'
        }, status=500)


@api_view(['POST'])
@authentication_classes([CookieJWTAuthentication])
@permission_classes([IsAuthenticated])
def api_update_vault(request, vault_id):
    """API para actualizar un vault existente"""
    try:
        data = json.loads(request.body)
        name = data.get('name', '').strip()
        description = data.get('description', '').strip()
        color = data.get('color', 'blue')
        
        # Obtener el vault
        try:
            vault = Vault.objects.get(id=vault_id, user=request.user)
        except Vault.DoesNotExist:
            return JsonResponse({
                'success': False,
                'error': 'Vault no encontrado'
            }, status=404)
        
        # Validaciones
        if not name:
            return JsonResponse({
                'success': False,
                'error': 'El nombre del vault es requerido'
            }, status=400)
        
        # Verificar nombre único (excluyendo el actual)
        if Vault.objects.filter(user=request.user, name=name).exclude(id=vault_id).exists():
            return JsonResponse({
                'success': False,
                'error': 'Ya tienes un vault con ese nombre'
            }, status=400)
        
        # Validar color
        valid_colors = [choice[0] for choice in Vault.VAULT_COLORS]
        if color not in valid_colors:
            return JsonResponse({
                'success': False,
                'error': 'Color de vault inválido'
            }, status=400)
        
        # Actualizar campos
        vault.name = name
        vault.description = description
        vault.color = color
        vault.save()
        
        # Log de actividad
        log_activity(
            user=request.user,
            activity_type='vault_updated',
            title='Vault actualizado',
            description=f'Vault "{name}" actualizado',
            severity='info'
        )
        
        return JsonResponse({
            'success': True,
            'message': 'Vault actualizado exitosamente',
            'vault': {
                'id': vault.id,
                'name': vault.name,
                'description': vault.description,
                'color': vault.color,
                'is_private': vault.is_private,
                'password_count': vault.get_password_count(),
                'updated_at': vault.updated_at.isoformat()
            }
        })
        
    except json.JSONDecodeError:
        return JsonResponse({
            'success': False,
            'error': 'Datos JSON inválidos'
        }, status=400)
    except Exception:
        logger.exception("Error actualizando vault")
        return JsonResponse({
            'success': False,
            'error': 'Error interno del servidor'
        }, status=500)


@api_view(['POST'])
@authentication_classes([CookieJWTAuthentication])
@permission_classes([IsAuthenticated])
def api_delete_vault(request, vault_id):
    """Elimina una bóveda (autorización zero-knowledge, Fase 2).

    La autorización ya no es la contraseña maestra en claro contra el `MasterKey` legado: el cliente
    deriva la AuthKey en local y prueba posesión con `guard_auth_key` (mismo bloqueo exponencial por
    usuario). Las contraseñas de la bóveda se mueven a otra (o a "sin bóveda"). Si la bóveda borrada
    es privada v2 —o el destino lo es— ese movimiento cambia de dominio de clave: el cliente debe
    re-cifrar las entradas y enviarlas en `ciphertexts` (fail-closed: sin ellas se rechaza con
    REENCRYPT_REQUIRED, nunca se guarda un blob indescifrable). Ambas privadas implicadas deben
    estar desbloqueadas.

    Espera { auth_key, move_passwords_to_vault?, ciphertexts? }.
    """
    try:
        data = json.loads(request.body)
        auth_key = data.get('auth_key')
        move_passwords_to_vault = data.get('move_passwords_to_vault')  # ID del vault destino o null
        ciphertexts = data.get('ciphertexts') or {}

        if not auth_key:
            return JsonResponse({
                'success': False,
                'error': 'Prueba de la contraseña maestra requerida'
            }, status=400)
        if not isinstance(ciphertexts, dict):
            return JsonResponse({'success': False, 'error': 'ciphertexts debe ser un objeto'}, status=400)

        # Verificar posesión de la maestra (bloqueo exponencial por usuario: 400/429/503).
        try:
            uc = UserCrypto.objects.get(user=request.user)
        except UserCrypto.DoesNotExist:
            return JsonResponse({
                'success': False,
                'error': 'No tienes una clave maestra configurada'
            }, status=400)
        denial = guard_auth_key(request.user, uc, auth_key)
        if denial is not None:
            return denial

        # Obtener el vault
        try:
            vault = Vault.objects.get(id=vault_id, user=request.user)
        except Vault.DoesNotExist:
            return JsonResponse({
                'success': False,
                'error': 'Vault no encontrado'
            }, status=404)

        # Vault destino (o None = "sin bóveda")
        destination_vault = None
        if move_passwords_to_vault:
            try:
                destination_vault = Vault.objects.get(id=move_passwords_to_vault, user=request.user)
            except Vault.DoesNotExist:
                return JsonResponse({
                    'success': False,
                    'error': 'Vault destino no encontrado'
                }, status=404)

        entries = list(vault.passwords.all())
        password_count = len(entries)

        # Movimiento entre dominios de clave: gatear las privadas implicadas y exigir el re-cifrado
        # ANTES de mutar nada (para no dejar el borrado a medias).
        cross_domain = password_count > 0 and (is_private_v2(vault) or is_private_v2(destination_vault))
        if cross_domain:
            denial = guard_private_vault_access(request.user, vault)
            if denial is not None:
                return denial
            if destination_vault is not None:
                denial = guard_private_vault_access(request.user, destination_vault)
                if denial is not None:
                    return denial
            if any(not ciphertexts.get(str(e.id)) for e in entries):
                return reencrypt_required_response()

        # Aplicar en una transacción: re-cifrar (si aplica) + mover, y sólo entonces borrar la
        # bóveda. Se reasigna cada entrada ANTES del delete para que el CASCADE no las arrastre.
        with transaction.atomic():
            for entry in entries:
                entry.vault = destination_vault
                update_fields = ['vault', 'updated_at']
                new_ct = ciphertexts.get(str(entry.id))
                if new_ct:
                    entry.ciphertext = new_ct
                    update_fields.append('ciphertext')
                entry.save(update_fields=update_fields)
            vault_name = vault.name
            vault.delete()

        # La bóveda ya no existe: olvidar su marcador de desbloqueo (lenient).
        clear_vault_unlock(request.user.id, vault_id)

        if password_count == 0:
            action_description = "no había contraseñas"
        elif move_passwords_to_vault:
            action_description = f"movidas a vault '{destination_vault.name}'"
        else:
            action_description = "movidas a 'Todas las contraseñas'"

        log_activity(
            user=request.user,
            activity_type='vault_deleted',
            title='Vault eliminado',
            description=f'Vault "{vault_name}" eliminado - {password_count} contraseñas {action_description}',
            severity='warning'
        )

        return JsonResponse({
            'success': True,
            'message': f'Vault "{vault_name}" eliminado exitosamente',
            'stats': {
                'passwords_moved': password_count,
                'destination': destination_vault.name if move_passwords_to_vault else 'Todas las contraseñas'
            }
        })

    except json.JSONDecodeError:
        return JsonResponse({
            'success': False,
            'error': 'Datos JSON inválidos'
        }, status=400)
    except Exception:
        logger.exception("Error eliminando vault")
        return JsonResponse({
            'success': False,
            'error': 'Error interno del servidor'
        }, status=500)


@api_view(['GET'])
@authentication_classes([CookieJWTAuthentication])
@permission_classes([IsAuthenticated])
def api_vault_crypto_params(request, vault_id):
    """Material que el cliente necesita para desbloquear una bóveda privada en local (paso 24).

    Espeja a `/api/master-key/params/`: `wrapped_vault_subkey` es opaco sin la contraseña del
    vault (sólo su SubEncKey lo desenvuelve), así que devolverlo al propio dueño no filtra nada.
    """
    try:
        try:
            vault = Vault.objects.get(id=vault_id, user=request.user)
        except Vault.DoesNotExist:
            return JsonResponse({'success': False, 'error': 'Vault no encontrado'}, status=404)

        if not vault.is_private or vault.vault_crypto_version < 2:
            return JsonResponse({
                'success': False,
                'error': 'La bóveda no es privada (o está en formato antiguo)',
            }, status=400)

        return JsonResponse({
            'success': True,
            'sub_kdf_salt': vault.sub_kdf_salt,
            'sub_kdf_params': vault.sub_kdf_params,
            'wrapped_vault_subkey': vault.wrapped_vault_subkey,
            'vault_crypto_version': vault.vault_crypto_version,
        })
    except Exception:
        logger.exception("Error obteniendo parámetros criptográficos del vault")
        return JsonResponse({'success': False, 'error': 'Error interno del servidor'}, status=500)


@api_view(['POST'])
@authentication_classes([CookieJWTAuthentication])
@permission_classes([IsAuthenticated])
def api_unlock_vault(request, vault_id):
    """Desbloquea una bóveda privada probando posesión de la subclave (paso 24, A9).

    El cliente deriva la SubAuthKey de la contraseña del vault (nunca la envía en claro) y la
    manda aquí. Si `guard_vault_auth_key` la valida, el servidor pone un marcador de desbloqueo
    (con TTL) que sustituye al viejo `vault_already_unlocked` de confianza del cliente.
    """
    try:
        data = json.loads(request.body)
        sub_auth_key = data.get('sub_auth_key')

        # Obtener el vault
        try:
            vault = Vault.objects.get(id=vault_id, user=request.user)
        except Vault.DoesNotExist:
            return JsonResponse({
                'success': False,
                'error': 'Vault no encontrado'
            }, status=404)

        # Si no es privado, no necesita desbloquearse
        if not vault.is_private:
            return JsonResponse({
                'success': True,
                'message': 'Vault público, no requiere desbloqueo'
            })

        if vault.vault_crypto_version < 2:
            return JsonResponse({
                'success': False,
                'error': 'La bóveda está en formato antiguo; debe recrearse.',
                'code': 'VAULT_LEGACY',
            }, status=400)

        if not sub_auth_key:
            return JsonResponse({
                'success': False,
                'error': 'Prueba de la contraseña del vault requerida'
            }, status=400)

        # Verificar posesión con bloqueo exponencial por bóveda (400/429/503).
        denial = guard_vault_auth_key(request.user, vault, sub_auth_key)
        if denial is not None:
            return denial

        # Registrar el desbloqueo en servidor (fail-closed si la caché no responde).
        try:
            mark_vault_unlocked(request.user.id, vault.id)
        except CacheUnavailable:
            return service_unavailable_response()

        log_activity(
            user=request.user,
            activity_type='vault_unlocked',
            title='Vault desbloqueado',
            description=f'Vault "{vault.name}" desbloqueado',
            severity='info',
            related_obj=vault,
        )

        return JsonResponse({
            'success': True,
            'message': f'Vault "{vault.name}" desbloqueado exitosamente'
        })

    except json.JSONDecodeError:
        return JsonResponse({
            'success': False,
            'error': 'Datos JSON inválidos'
        }, status=400)
    except Exception:
        logger.exception("Error desbloqueando vault")
        return JsonResponse({
            'success': False,
            'error': 'Error interno del servidor'
        }, status=500)
        
        
        
@api_view(['GET'])
@authentication_classes([CookieJWTAuthentication])
@permission_classes([IsAuthenticated])
def api_vault_stats(request):
    """API para estadísticas generales de vaults del usuario"""
    try:
        user_vaults = Vault.objects.filter(user=request.user)
        total_passwords = PasswordEntry.objects.filter(user=request.user).count()
        
        stats = {
            'total_vaults': user_vaults.count(),
            'private_vaults': user_vaults.filter(is_private=True).count(),
            'public_vaults': user_vaults.filter(is_private=False).count(),
            'total_passwords': total_passwords,
            'unvaulted_passwords': PasswordEntry.objects.filter(user=request.user, vault__isnull=True).count(),
            'vaulted_passwords': PasswordEntry.objects.filter(user=request.user, vault__isnull=False).count(),
            'vault_colors_used': list(user_vaults.values_list('color', flat=True).distinct()),
            'largest_vault': None,
            'most_used_color': None
        }
        
        # Encontrar el vault más grande
        if user_vaults.exists():
            vault_sizes = []
            for vault in user_vaults:
                count = vault.get_password_count()
                vault_sizes.append({
                    'vault_name': vault.name,
                    'password_count': count
                })
            
            if vault_sizes:
                largest = max(vault_sizes, key=lambda x: x['password_count'])
                stats['largest_vault'] = largest
            
            # Color más usado
            from collections import Counter
            colors = list(user_vaults.values_list('color', flat=True))
            if colors:
                color_counts = Counter(colors)
                stats['most_used_color'] = color_counts.most_common(1)[0][0]
        
        return JsonResponse({
            'success': True,
            'stats': stats
        })
        
    except Exception:
        logger.exception("Error en api_vault_stats")
        return JsonResponse({
            'success': False,
            'error': 'Error obteniendo estadísticas de vaults'
        }, status=500)


@api_view(['POST'])
@authentication_classes([CookieJWTAuthentication])
@permission_classes([IsAuthenticated])
def api_change_vault_password(request, vault_id):
    """Rota la contraseña de una bóveda privada (paso 24, zero-knowledge).

    El cliente re-envuelve la MISMA VaultSubKey con la SubEncKey nueva (rotateVaultPassword) —no
    re-cifra las entradas— y envía: `current_sub_auth_key` (prueba de la contraseña actual) y el
    material nuevo { sub_kdf_salt, sub_kdf_params, sub_auth_key, wrapped_vault_subkey }. El
    servidor verifica posesión de la actual y reemplaza el material. Nunca ve ninguna contraseña.
    """
    try:
        data = json.loads(request.body)
        current_sub_auth_key = data.get('current_sub_auth_key')
        new_sub_kdf_salt = data.get('sub_kdf_salt')
        new_sub_auth_key = data.get('sub_auth_key')
        new_wrapped_vault_subkey = data.get('wrapped_vault_subkey')
        new_sub_kdf_params = data.get('sub_kdf_params') or {}

        if not current_sub_auth_key:
            return JsonResponse({
                'success': False,
                'error': 'Prueba de la contraseña actual del vault requerida'
            }, status=400)
        if not all([new_sub_kdf_salt, new_sub_auth_key, new_wrapped_vault_subkey]):
            return JsonResponse({
                'success': False,
                'error': 'Falta el material criptográfico nuevo de la bóveda'
            }, status=400)
        if not isinstance(new_sub_kdf_params, dict):
            return JsonResponse({
                'success': False,
                'error': 'sub_kdf_params debe ser un objeto'
            }, status=400)

        # Obtener el vault
        try:
            vault = Vault.objects.get(id=vault_id, user=request.user)
        except Vault.DoesNotExist:
            return JsonResponse({
                'success': False,
                'error': 'Vault no encontrado'
            }, status=404)

        # Verificar que es privado zero-knowledge
        if not vault.is_private or vault.vault_crypto_version < 2:
            return JsonResponse({
                'success': False,
                'error': 'Solo las bóvedas privadas (v2) tienen contraseña'
            }, status=400)

        # Verificar posesión de la contraseña actual (bloqueo exponencial por bóveda).
        denial = guard_vault_auth_key(request.user, vault, current_sub_auth_key)
        if denial is not None:
            return denial

        # Reemplazar el material por el nuevo (misma VaultSubKey, nueva envoltura).
        vault.sub_kdf_salt = new_sub_kdf_salt
        vault.sub_kdf_params = new_sub_kdf_params
        vault.wrapped_vault_subkey = new_wrapped_vault_subkey
        vault.set_sub_auth_key(new_sub_auth_key)
        vault.save()

        # La contraseña cambió: invalidar el desbloqueo en servidor para forzar re-prueba.
        clear_vault_unlock(request.user.id, vault.id)

        # Log de actividad
        log_activity(
            user=request.user,
            activity_type='vault_updated',
            title='Contraseña de vault cambiada',
            description=f'Contraseña del vault "{vault.name}" actualizada',
            severity='info'
        )

        return JsonResponse({
            'success': True,
            'message': f'Contraseña del vault "{vault.name}" cambiada exitosamente'
        })

    except json.JSONDecodeError:
        return JsonResponse({
            'success': False,
            'error': 'Datos JSON inválidos'
        }, status=400)
    except Exception:
        logger.exception("Error cambiando contraseña de vault")
        return JsonResponse({
            'success': False,
            'error': 'Error interno del servidor'
        }, status=500)


@api_view(['POST'])
@authentication_classes([CookieJWTAuthentication])
@permission_classes([IsAuthenticated])
def api_convert_vault_privacy(request, vault_id):
    """Convierte una bóveda entre pública y privada re-cifrando su contenido (paso 24b).

    Cambiar de privacidad cambia el dominio de clave de TODAS las entradas de la bóveda (VaultKey
    principal ↔ VaultSubKey), así que el cliente descifra y re-cifra cada una y envía el mapa
    completo `ciphertexts = { "<id>": "<b64>" }`. El servidor lo aplica en una transacción y exige
    que estén TODAS (o ninguna, si la bóveda está vacía): dejar una entrada sin re-cifrar la haría
    indescifrable con la clave nueva.

    - público → privado: además { sub_kdf_salt, sub_kdf_params, sub_auth_key, wrapped_vault_subkey }
      (material de subclave, como en create). El servidor nunca ve la contraseña del vault.
    - privado → público: además { current_sub_auth_key } (prueba de posesión de la subclave actual,
      verificada con el bloqueo por bóveda). Se borra el material de subclave.
    """
    try:
        data = json.loads(request.body)
        make_private = bool(data.get('make_private', False))
        ciphertexts = data.get('ciphertexts') or {}
        if not isinstance(ciphertexts, dict):
            return JsonResponse({'success': False, 'error': 'ciphertexts debe ser un objeto'}, status=400)

        # Obtener el vault
        try:
            vault = Vault.objects.get(id=vault_id, user=request.user)
        except Vault.DoesNotExist:
            return JsonResponse({'success': False, 'error': 'Vault no encontrado'}, status=404)

        # Verificar que hay cambio real
        if vault.is_private == make_private:
            status_text = "privada" if make_private else "pública"
            return JsonResponse({'success': False, 'error': f'La bóveda ya es {status_text}'}, status=400)

        entries = list(PasswordEntry.objects.filter(user=request.user, vault=vault))
        entry_ids = {e.id for e in entries}

        # Completitud: el mapa debe cubrir EXACTAMENTE las entradas de la bóveda.
        try:
            provided_ids = {int(k) for k in ciphertexts.keys()}
        except (ValueError, TypeError):
            return JsonResponse({'success': False, 'error': 'ids inválidos en ciphertexts'}, status=400)
        if provided_ids != entry_ids:
            return JsonResponse({
                'success': False,
                'error': 'Debes re-cifrar exactamente todas las entradas de la bóveda.',
                'code': 'REENCRYPT_INCOMPLETE',
            }, status=400)

        if make_private:
            sub_kdf_salt = data.get('sub_kdf_salt')
            sub_auth_key = data.get('sub_auth_key')
            wrapped_vault_subkey = data.get('wrapped_vault_subkey')
            sub_kdf_params = data.get('sub_kdf_params') or {}
            if not all([sub_kdf_salt, sub_auth_key, wrapped_vault_subkey]):
                return JsonResponse({
                    'success': False,
                    'error': 'Falta el material criptográfico de la bóveda privada',
                }, status=400)
            if not isinstance(sub_kdf_params, dict):
                return JsonResponse({'success': False, 'error': 'sub_kdf_params debe ser un objeto'}, status=400)

            with transaction.atomic():
                for entry in entries:
                    entry.ciphertext = ciphertexts[str(entry.id)]
                    entry.crypto_version = 2
                    entry.save(update_fields=['ciphertext', 'crypto_version', 'updated_at'])
                vault.is_private = True
                vault.vault_crypto_version = 2
                vault.sub_kdf_salt = sub_kdf_salt
                vault.sub_kdf_params = sub_kdf_params
                vault.wrapped_vault_subkey = wrapped_vault_subkey
                vault.set_sub_auth_key(sub_auth_key)
                vault.save()

            # Quien acaba de convertirla posee la subclave: se deja desbloqueada (best-effort).
            try:
                mark_vault_unlocked(request.user.id, vault.id)
            except CacheUnavailable:
                logger.warning("No se pudo marcar la bóveda %s como desbloqueada al convertirla", vault.id)
        else:
            # privado → público: exige prueba de posesión de la subclave actual.
            if vault.vault_crypto_version < 2:
                return JsonResponse({
                    'success': False,
                    'error': 'La bóveda está en formato antiguo; debe recrearse.',
                    'code': 'VAULT_LEGACY',
                }, status=400)
            current_sub_auth_key = data.get('current_sub_auth_key')
            if not current_sub_auth_key:
                return JsonResponse({
                    'success': False,
                    'error': 'Prueba de la contraseña del vault requerida',
                }, status=400)
            denial = guard_vault_auth_key(request.user, vault, current_sub_auth_key)
            if denial is not None:
                return denial

            with transaction.atomic():
                for entry in entries:
                    entry.ciphertext = ciphertexts[str(entry.id)]
                    entry.crypto_version = 2
                    entry.save(update_fields=['ciphertext', 'crypto_version', 'updated_at'])
                vault.is_private = False
                vault.vault_crypto_version = 1
                vault.sub_kdf_salt = None
                vault.sub_kdf_params = {}
                vault.sub_auth_key_hash = None
                vault.wrapped_vault_subkey = None
                vault.save()

            clear_vault_unlock(request.user.id, vault.id)

        action_text = "convertida a privada" if make_private else "convertida a pública"
        log_activity(
            user=request.user,
            activity_type='vault_updated',
            title='Privacidad de vault cambiada',
            description=f'Bóveda "{vault.name}" {action_text} ({len(entries)} entradas re-cifradas)',
            severity='info'
        )

        return JsonResponse({
            'success': True,
            'message': f'Bóveda "{vault.name}" {action_text} exitosamente',
            'vault': {
                'id': vault.id,
                'name': vault.name,
                'is_private': vault.is_private
            }
        })

    except json.JSONDecodeError:
        return JsonResponse({
            'success': False,
            'error': 'Datos JSON inválidos'
        }, status=400)
    except Exception:
        logger.exception("Error cambiando privacidad de vault")
        return JsonResponse({
            'success': False,
            'error': 'Error interno del servidor'
        }, status=500)



@api_view(['POST'])
@authentication_classes([CookieJWTAuthentication])
@permission_classes([IsAuthenticated])
def api_vault_search(request):
    """API para buscar vaults y contraseñas dentro de vaults"""
    try:
        query = request.GET.get('q', '').strip()
        vault_id = request.GET.get('vault_id')
        
        if not query:
            return JsonResponse({
                'success': False,
                'error': 'Query de búsqueda requerida'
            }, status=400)
        
        results = {
            'vaults': [],
            'passwords': [],
            'query': query
        }
        
        # Buscar vaults por nombre
        matching_vaults = Vault.objects.filter(
            user=request.user,
            name__icontains=query
        )
        
        for vault in matching_vaults:
            results['vaults'].append({
                'id': vault.id,
                'name': vault.name,
                'description': vault.description,
                'color': vault.color,
                'is_private': vault.is_private,
                'password_count': vault.get_password_count()
            })
        
        # Búsqueda por contenido de contraseñas (sitio/usuario): en v2 esos datos van cifrados
        # dentro del ciphertext (zero-knowledge), así que el SERVIDOR no puede buscarlos. La SPA
        # descifra en local y filtra allí. Aquí sólo se buscan bóvedas por nombre (metadato en
        # claro). `results['passwords']` queda vacío a propósito.

        return JsonResponse({
            'success': True,
            'results': results,
            'total_results': len(results['vaults']) + len(results['passwords'])
        })
        
    except Exception:
        logger.exception("Error en api_vault_search")
        return JsonResponse({
            'success': False,
            'error': 'Error en la búsqueda'
        }, status=500)