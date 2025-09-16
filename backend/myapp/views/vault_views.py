from django.http import JsonResponse
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.http import require_http_methods
from django.contrib.auth.decorators import login_required
from django.utils import timezone
from django.db import transaction

import json

from ..models import Vault, PasswordEntry, MasterKey
from ..utils.logging_utils import log_activity 


@login_required
@require_http_methods(["GET"])
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
        
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': 'Error obteniendo vaults',
            'details': str(e)
        }, status=500)


@login_required
@require_http_methods(["POST"])
@csrf_protect
def api_create_vault(request):
    """API para crear un nuevo vault"""
    try:
        data = json.loads(request.body)
        name = data.get('name', '').strip()
        description = data.get('description', '').strip()
        color = data.get('color', 'blue')
        is_private = data.get('is_private', False)
        vault_password = data.get('vault_password', '').strip() if is_private else None
        
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
        
        # Para vaults privados, validar contraseña
        if is_private:
            if not vault_password:
                return JsonResponse({
                    'success': False,
                    'error': 'Los vaults privados requieren una contraseña'
                }, status=400)
            
            if len(vault_password) < 6:
                return JsonResponse({
                    'success': False,
                    'error': 'La contraseña del vault debe tener al menos 6 caracteres'
                }, status=400)
        
        # Crear el vault
        vault = Vault.objects.create(
            user=request.user,
            name=name,
            description=description,
            color=color,
            is_private=is_private
        )
        
        # Establecer contraseña si es privado
        if is_private and vault_password:
            vault.set_vault_password(vault_password)
            vault.save()
        
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
    except Exception as e:
        print(f"Error creando vault: {e}")
        return JsonResponse({
            'success': False,
            'error': 'Error interno del servidor'
        }, status=500)


@login_required
@require_http_methods(["POST"])
@csrf_protect
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
    except Exception as e:
        print(f"Error actualizando vault: {e}")
        return JsonResponse({
            'success': False,
            'error': 'Error interno del servidor'
        }, status=500)


@login_required
@require_http_methods(["POST"])
@csrf_protect
def api_delete_vault(request, vault_id):
    """API para eliminar un vault"""
    try:
        data = json.loads(request.body)
        master_password = data.get('master_password', '').strip()
        move_passwords_to_vault = data.get('move_passwords_to_vault')  # ID del vault destino o null
        
        if not master_password:
            return JsonResponse({
                'success': False,
                'error': 'Master password requerida'
            }, status=400)
        
        # Verificar master password
        try:
            master_key_entry = MasterKey.objects.get(user=request.user)
            if not master_key_entry.verify_master_key(master_password):
                return JsonResponse({
                    'success': False,
                    'error': 'Master password incorrecta'
                }, status=400)
        except MasterKey.DoesNotExist:
            return JsonResponse({
                'success': False,
                'error': 'No se encontró la clave maestra'
            }, status=400)
        
        # Obtener el vault
        try:
            vault = Vault.objects.get(id=vault_id, user=request.user)
        except Vault.DoesNotExist:
            return JsonResponse({
                'success': False,
                'error': 'Vault no encontrado'
            }, status=404)
        
        # Contar contraseñas en el vault
        passwords_in_vault = vault.passwords.all()
        password_count = passwords_in_vault.count()
        
        # Manejar contraseñas del vault que se va a eliminar
        if password_count > 0:
            if move_passwords_to_vault:
                # Mover a otro vault
                try:
                    destination_vault = Vault.objects.get(id=move_passwords_to_vault, user=request.user)
                    passwords_in_vault.update(vault=destination_vault)
                    action_description = f"movidas a vault '{destination_vault.name}'"
                except Vault.DoesNotExist:
                    return JsonResponse({
                        'success': False,
                        'error': 'Vault destino no encontrado'
                    }, status=404)
            else:
                # Mover a "sin vault" (null)
                passwords_in_vault.update(vault=None)
                action_description = "movidas a 'Todas las contraseñas'"
        else:
            action_description = "no había contraseñas"
        
        vault_name = vault.name
        vault.delete()
        
        # Log de actividad
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
    except Exception as e:
        print(f"Error eliminando vault: {e}")
        return JsonResponse({
            'success': False,
            'error': 'Error interno del servidor'
        }, status=500)


@login_required
@require_http_methods(["POST"])
@csrf_protect
def api_unlock_vault(request, vault_id):
    """API para desbloquear un vault privado"""
    try:
        data = json.loads(request.body)
        vault_password = data.get('vault_password', '').strip()
        
        if not vault_password:
            return JsonResponse({
                'success': False,
                'error': 'Contraseña del vault requerida'
            }, status=400)
        
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
        
        # Verificar contraseña del vault
        if not vault.verify_vault_password(vault_password):
            return JsonResponse({
                'success': False,
                'error': 'Contraseña del vault incorrecta'
            }, status=400)
        
        return JsonResponse({
            'success': True,
            'message': f'Vault "{vault.name}" desbloqueado exitosamente'
        })
        
    except json.JSONDecodeError:
        return JsonResponse({
            'success': False,
            'error': 'Datos JSON inválidos'
        }, status=400)
    except Exception as e:
        print(f"Error desbloqueando vault: {e}")
        return JsonResponse({
            'success': False,
            'error': 'Error interno del servidor'
        }, status=500)
        
        
        
@login_required
@require_http_methods(["GET"])
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
        
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': 'Error obteniendo estadísticas de vaults',
            'details': str(e)
        }, status=500)


@login_required
@require_http_methods(["POST"])
@csrf_protect
def api_change_vault_password(request, vault_id):
    """API para cambiar la contraseña de un vault privado"""
    try:
        data = json.loads(request.body)
        current_vault_password = data.get('current_vault_password', '').strip()
        new_vault_password = data.get('new_vault_password', '').strip()
        master_password = data.get('master_password', '').strip()
        
        if not all([current_vault_password, new_vault_password, master_password]):
            return JsonResponse({
                'success': False,
                'error': 'Todas las contraseñas son requeridas'
            }, status=400)
        
        # Verificar master password
        try:
            master_key_entry = MasterKey.objects.get(user=request.user)
            if not master_key_entry.verify_master_key(master_password):
                return JsonResponse({
                    'success': False,
                    'error': 'Master password incorrecta'
                }, status=400)
        except MasterKey.DoesNotExist:
            return JsonResponse({
                'success': False,
                'error': 'No se encontró la clave maestra'
            }, status=400)
        
        # Obtener el vault
        try:
            vault = Vault.objects.get(id=vault_id, user=request.user)
        except Vault.DoesNotExist:
            return JsonResponse({
                'success': False,
                'error': 'Vault no encontrado'
            }, status=404)
        
        # Verificar que es privado
        if not vault.is_private:
            return JsonResponse({
                'success': False,
                'error': 'Solo los vaults privados tienen contraseña'
            }, status=400)
        
        # Verificar contraseña actual
        if not vault.verify_vault_password(current_vault_password):
            return JsonResponse({
                'success': False,
                'error': 'Contraseña actual del vault incorrecta'
            }, status=400)
        
        # Validar nueva contraseña
        if len(new_vault_password) < 6:
            return JsonResponse({
                'success': False,
                'error': 'La nueva contraseña debe tener al menos 6 caracteres'
            }, status=400)
        
        # Cambiar contraseña
        vault.set_vault_password(new_vault_password)
        vault.save()
        
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
    except Exception as e:
        print(f"Error cambiando contraseña de vault: {e}")
        return JsonResponse({
            'success': False,
            'error': 'Error interno del servidor'
        }, status=500)


@login_required
@require_http_methods(["POST"])
@csrf_protect
def api_convert_vault_privacy(request, vault_id):
    """API para convertir un vault entre público y privado"""
    try:
        data = json.loads(request.body)
        make_private = data.get('make_private', False)
        vault_password = data.get('vault_password', '').strip() if make_private else None
        master_password = data.get('master_password', '').strip()
        
        if not master_password:
            return JsonResponse({
                'success': False,
                'error': 'Master password requerida'
            }, status=400)
        
        # Verificar master password
        try:
            master_key_entry = MasterKey.objects.get(user=request.user)
            if not master_key_entry.verify_master_key(master_password):
                return JsonResponse({
                    'success': False,
                    'error': 'Master password incorrecta'
                }, status=400)
        except MasterKey.DoesNotExist:
            return JsonResponse({
                'success': False,
                'error': 'No se encontró la clave maestra'
            }, status=400)
        
        # Obtener el vault
        try:
            vault = Vault.objects.get(id=vault_id, user=request.user)
        except Vault.DoesNotExist:
            return JsonResponse({
                'success': False,
                'error': 'Vault no encontrado'
            }, status=404)
        
        # Verificar que hay cambio real
        if vault.is_private == make_private:
            status_text = "privado" if make_private else "público"
            return JsonResponse({
                'success': False,
                'error': f'El vault ya es {status_text}'
            }, status=400)
        
        # Si se convierte a privado, validar contraseña
        if make_private:
            if not vault_password:
                return JsonResponse({
                    'success': False,
                    'error': 'Contraseña del vault requerida para hacerlo privado'
                }, status=400)
            
            if len(vault_password) < 6:
                return JsonResponse({
                    'success': False,
                    'error': 'La contraseña del vault debe tener al menos 6 caracteres'
                }, status=400)
            
            # Establecer como privado
            vault.is_private = True
            vault.set_vault_password(vault_password)
        else:
            # Convertir a público
            vault.is_private = False
            vault.vault_password_hash = None
            vault.vault_salt = None
        
        vault.save()
        
        action_text = "convertido a privado" if make_private else "convertido a público"
        
        # Log de actividad
        log_activity(
            user=request.user,
            activity_type='vault_updated',
            title='Privacidad de vault cambiada',
            description=f'Vault "{vault.name}" {action_text}',
            severity='info'
        )
        
        return JsonResponse({
            'success': True,
            'message': f'Vault "{vault.name}" {action_text} exitosamente',
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
    except Exception as e:
        print(f"Error cambiando privacidad de vault: {e}")
        return JsonResponse({
            'success': False,
            'error': 'Error interno del servidor'
        }, status=500)



@login_required
@require_http_methods(["GET"])
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
        
        # Buscar contraseñas
        password_filter = PasswordEntry.objects.filter(user=request.user)
        
        # Si se especifica un vault, buscar solo en ese vault
        if vault_id:
            if vault_id == 'unvaulted':
                password_filter = password_filter.filter(vault__isnull=True)
            else:
                try:
                    vault_id_int = int(vault_id)
                    password_filter = password_filter.filter(vault_id=vault_id_int)
                except ValueError:
                    return JsonResponse({
                        'success': False,
                        'error': 'ID de vault inválido'
                    }, status=400)
        
        # Buscar por website o username
        matching_passwords = password_filter.filter(
            Vault.Q(website__icontains=query) | 
            Vault.Q(username__icontains=query)
        )
        
        for password in matching_passwords:
            results['passwords'].append({
                'id': password.id,
                'website': password.website,
                'username': password.username,
                'vault_id': password.vault_id,
                'vault_name': password.vault.name if password.vault else None,
                'created_at': password.created_at.isoformat()
            })
        
        return JsonResponse({
            'success': True,
            'results': results,
            'total_results': len(results['vaults']) + len(results['passwords'])
        })
        
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': 'Error en la búsqueda',
            'details': str(e)
        }, status=500)