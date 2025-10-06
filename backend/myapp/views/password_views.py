from rest_framework.decorators import api_view, permission_classes,authentication_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.authentication import JWTAuthentication
from django.http import JsonResponse
from django.views import View
from django.shortcuts import get_object_or_404

import json

from ..models import PasswordEntry,MasterKey,Vault
from ..encryption_utils import encrypt_password,decrypt_password
from ..utils.logging_utils import log_activity


@api_view(['GET'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def api_accounts(request):
    """API para obtener cuentas del usuario"""
    accounts = PasswordEntry.objects.filter(user=request.user)
    data = [{
        'id': acc.id,
        'website': acc.website,
        'username': acc.username,
        'encryption_algorithm': acc.encryption_algorithm,
        'encrypted_password': acc.encrypted_password,
        'salt': acc.salt,
        'iv_or_nonce': acc.iv_or_nonce,
        'encrypted_key': acc.encrypted_key
    } for acc in accounts]
    return JsonResponse({'accounts': data})

@api_view(['POST'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def api_unlock_password(request, password_id):
    """API para desbloquear una contraseña específica"""
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    try:
        data = json.loads(request.body)
        master_password = data.get('master_password')
        
        if not master_password:
            return JsonResponse({'error': 'Master password requerida'}, status=400)
        
        master_key_entry = get_object_or_404(MasterKey, user=request.user)
        if not master_key_entry.verify_master_key(master_password):
            return JsonResponse({'error': 'Master password incorrecta'}, status=400)
        
        account = get_object_or_404(PasswordEntry, id=password_id, user=request.user)
        
        decrypted_password = decrypt_password(
            encrypted_password=account.encrypted_password,
            encrypted_key=account.encrypted_key, 
            iv_or_nonce=account.iv_or_nonce,
            master_key=master_key_entry.hashed_key.encode(),
            entry_salt=account.salt,
            algorithm=account.encryption_algorithm
        )
        
        return JsonResponse({
            'success': True,
            'password': decrypted_password.decode('utf-8'),
            'account': {
                'id': account.id,
                'website': account.website,
                'username': account.username
            }
        })
        
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@api_view(['GET'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def api_unlock_all_accounts(request):
    """API para desbloquear todas las cuentas"""
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    
    try:
        data = json.loads(request.body)
        master_password = data.get('master_password')
        
        if not master_password:
            return JsonResponse({'error': 'Master password requerida'}, status=400)
        
        master_key_entry = get_object_or_404(MasterKey, user=request.user)
        if not master_key_entry.verify_master_key(master_password):
            return JsonResponse({'error': 'Master password incorrecta'}, status=400)
        
        accounts = PasswordEntry.objects.filter(user=request.user)
        decrypted_accounts = []
        
        for account in accounts:
            try:
                decrypted_password = decrypt_password(
                    account.encrypted_password, 
                    account.encrypted_key, 
                    account.iv_or_nonce, 
                    master_key_entry.hashed_key.encode(), 
                    account.encryption_algorithm
                )
                decrypted_accounts.append({
                    'id': account.id,
                    'website': account.website,
                    'username': account.username,
                    'password': decrypted_password.decode('utf-8'),
                    'encryption_algorithm': account.encryption_algorithm
                })
            except Exception as e:
                # Si hay error desencriptando una cuenta, la omitimos
                continue
        
        return JsonResponse({
            'success': True,
            'accounts': decrypted_accounts
        })
        
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)
    
    

@api_view(['POST'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def delete_password(request, password_id):
    """Eliminar entrada de contraseña - Solo API JSON"""
    try:
        data = json.loads(request.body)
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
        
        # Obtener y eliminar contraseña
        try:
            password_entry = PasswordEntry.objects.get(id=password_id, user=request.user)
            website_name = password_entry.website
            
            password_entry.delete()
            
            # Log de actividad
            log_activity(
                user=request.user,
                activity_type='password_deleted',
                title='Contraseña eliminada',
                description=f'Contraseña de {website_name} eliminada',
                severity='warning'
            )
            
            return JsonResponse({
                'success': True,
                'message': 'Contraseña eliminada exitosamente'
            })
            
        except PasswordEntry.DoesNotExist:
            return JsonResponse({
                'success': False,
                'error': 'Contraseña no encontrada'
            }, status=404)
            
    except json.JSONDecodeError:
        return JsonResponse({
            'success': False,
            'error': 'Datos JSON inválidos'
        }, status=400)
    except Exception as e:
        print(f"Error deleting password: {e}")
        return JsonResponse({
            'success': False,
            'error': 'Error interno del servidor'
        }, status=500)


@api_view(['POST'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def update_password(request, pk):
    """Actualizar entrada de contraseña - Solo API JSON"""
    try:
        data = json.loads(request.body)
        website = data.get('website', '').strip()
        username = data.get('username', '').strip()
        password = data.get('password', '')  # Puede ser vacío si no quieren cambiarla
        algorithm = data.get('algorithm', 'AES')
        master_password = data.get('master_password', '').strip()
        
        # Validaciones básicas
        if not website:
            return JsonResponse({
                'success': False,
                'error': 'El sitio web es requerido'
            }, status=400)
        
        if not username:
            return JsonResponse({
                'success': False,
                'error': 'El nombre de usuario es requerido'
            }, status=400)
        
        if algorithm not in ['AES', 'ChaCha20']:
            return JsonResponse({
                'success': False,
                'error': 'Algoritmo de encriptación inválido'
            }, status=400)
        
        # Si van a cambiar la contraseña, validar que esté presente y sea válida
        if password and len(password) < 8:
            return JsonResponse({
                'success': False,
                'error': 'La contraseña debe tener al menos 8 caracteres'
            }, status=400)
        
        # Si van a cambiar contraseña, necesitamos master password
        if password and not master_password:
            return JsonResponse({
                'success': False,
                'error': 'Master password requerida para cambiar contraseña'
            }, status=400)
        
        # Obtener entrada de contraseña
        try:
            password_entry = PasswordEntry.objects.get(id=pk, user=request.user)
        except PasswordEntry.DoesNotExist:
            return JsonResponse({
                'success': False,
                'error': 'Contraseña no encontrada'
            }, status=404)
        
        # Si van a cambiar contraseña, verificar master password
        if password and master_password:
            try:
                master_key_entry = MasterKey.objects.get(user=request.user)
                if not master_key_entry.verify_master_key(master_password):
                    return JsonResponse({
                        'success': False,
                        'error': 'Master password incorrecta'
                    }, status=400)
                
                # Re-encriptar con nueva contraseña
                master_key = master_key_entry.hashed_key.encode()
                encrypted_password, encrypted_key, iv_or_nonce, entry_salt = encrypt_password(
                    password, master_key, algorithm
                )
                
                password_entry.encrypted_password = encrypted_password
                password_entry.encrypted_key = encrypted_key
                password_entry.iv_or_nonce = iv_or_nonce
                password_entry.salt = entry_salt
                password_entry.encryption_algorithm = algorithm
                
            except MasterKey.DoesNotExist:
                return JsonResponse({
                    'success': False,
                    'error': 'No se encontró la clave maestra'
                }, status=400)
        
        # Limpiar website URL
        clean_website = website.replace('https://', '').replace('http://', '').replace('www.', '')
        
        # Actualizar campos básicos
        password_entry.website = clean_website
        password_entry.username = username
        
        # Solo actualizar algoritmo si no se cambió la contraseña
        if not password:
            password_entry.encryption_algorithm = algorithm
        
        password_entry.save()
        
        # Log de actividad
        log_activity(
            user=request.user,
            activity_type='password_updated',
            title='Contraseña actualizada',
            description=f'Contraseña de {clean_website} actualizada',
            severity='success'
        )

        return JsonResponse({
            'success': True,
            'message': 'Contraseña actualizada exitosamente'
        })
        
    except json.JSONDecodeError:
        return JsonResponse({
            'success': False,
            'error': 'Datos JSON inválidos'
        }, status=400)
    except Exception as e:
        print(f"Error updating password: {e}")
        return JsonResponse({
            'success': False,
            'error': 'Error interno del servidor'
        }, status=500)


# En password_views.py - Actualizar el método add_password_with_vault_support existente

@api_view(['POST'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def add_password_with_vault_support(request):
    """Versión modificada de add_password que soporta vaults con optimización de unlock"""
    try:
        data = json.loads(request.body)
        website = data.get('website', '').strip()
        username = data.get('username', '').strip()
        password = data.get('password', '')
        algorithm = data.get('algorithm', 'AES')
        vault_id = data.get('vault_id')
        vault_password = data.get('vault_password', '').strip()
        
        # NUEVO: Flag para indicar si el vault ya está desbloqueado en el frontend
        vault_already_unlocked = data.get('vault_already_unlocked', False)

        # AÑADIR ESTOS LOGS DE DIAGNÓSTICO
        print(f"🔍 Usuario autenticado: {request.user}")
        print(f"🔍 Usuario ID: {request.user.id if request.user else 'None'}")
        print(f"🔍 Usuario autenticado: {request.user.is_authenticated}")
        print(f"🔍 Buscando MasterKey para user_id: {request.user.id}")
        
        # Validaciones básicas (mantener las existentes)
        if not website:
            return JsonResponse({
                'success': False,
                'error': 'El sitio web es requerido'
            }, status=400)
        
        if not username:
            return JsonResponse({
                'success': False,
                'error': 'El nombre de usuario es requerido'
            }, status=400)
        
        if not password:
            return JsonResponse({
                'success': False,
                'error': 'La contraseña es requerida'
            }, status=400)
        
        if len(password) < 8:
            return JsonResponse({
                'success': False,
                'error': 'La contraseña debe tener al menos 8 caracteres'
            }, status=400)
        
        if algorithm not in ['AES', 'ChaCha20']:
            return JsonResponse({
                'success': False,
                'error': 'Algoritmo de encriptación inválido'
            }, status=400)
        
        # Limpiar website URL
        clean_website = website.replace('https://', '').replace('http://', '').replace('www.', '')
        
        # Obtener master key
        try:
            master_key_entry = MasterKey.objects.get(user=request.user)
            master_key = master_key_entry.hashed_key.encode()
        except MasterKey.DoesNotExist:
            return JsonResponse({
                'success': False,
                'error': 'No se encontró la clave maestra'
            }, status=400)
            
        # Validación para vault - MODIFICADA
        vault = None
        if vault_id:
            try:
                vault = Vault.objects.get(id=vault_id, user=request.user)
                
                # Si el vault es privado
                if vault.is_private:
                    # Si el vault ya está desbloqueado en el frontend, no requerir contraseña
                    if vault_already_unlocked:
                        # El frontend nos dice que el vault ya está desbloqueado
                        # Solo verificamos que tengamos una sesión activa válida
                        pass
                    else:
                        # El vault no está desbloqueado, requerir contraseña
                        if not vault_password:
                            return JsonResponse({
                                'success': False,
                                'error': 'Contraseña del vault requerida'
                            }, status=400)
                        
                        if not vault.verify_vault_password(vault_password):
                            return JsonResponse({
                                'success': False,
                                'error': 'Contraseña del vault incorrecta'
                            }, status=400)
                        
            except Vault.DoesNotExist:
                return JsonResponse({
                    'success': False,
                    'error': 'Vault no encontrado'
                }, status=400)
                
        # Encriptar contraseña (mantener igual)
        encrypted_password, encrypted_key, iv_or_nonce, entry_salt = encrypt_password(
            password, master_key, algorithm
        )
        
        # Crear entrada (mantener igual)
        password_entry = PasswordEntry.objects.create(
            user=request.user,
            website=clean_website,
            username=username,
            encrypted_password=encrypted_password,
            encryption_algorithm=algorithm,
            iv_or_nonce=iv_or_nonce,
            encrypted_key=encrypted_key,
            salt=entry_salt,
            vault=vault
        )
        
        # Log modificado
        vault_info = f' en vault "{vault.name}"' if vault else ''
        unlock_info = ' (vault ya desbloqueado)' if vault_already_unlocked and vault and vault.is_private else ''
        
        log_activity(
            user=request.user,
            activity_type='password_created',
            title='Nueva contraseña creada',
            description=f'Contraseña creada para {clean_website}{vault_info}{unlock_info}',
            severity='success',
            related_obj=password_entry
        )
        
        return JsonResponse({
            'success': True,
            'message': 'Contraseña creada exitosamente',
            'password_id': password_entry.id,
            'vault': vault.name if vault else None,
            'vault_was_unlocked': vault_already_unlocked
        })
        
    except json.JSONDecodeError:
        return JsonResponse({
            'success': False,
            'error': 'Datos JSON inválidos'
        }, status=400)
    except Exception as e:
        print(f"Error creating password: {e}")
        return JsonResponse({
            'success': False,
            'error': 'Error interno del servidor'
        }, status=500)
        
        
        
@api_view(['GET'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def api_vault_passwords(request, vault_id):
    """API para obtener contraseñas de un vault específico"""
    try:
        # Obtener el vault
        try:
            vault = Vault.objects.get(id=vault_id, user=request.user)
        except Vault.DoesNotExist:
            return JsonResponse({
                'success': False,
                'error': 'Vault no encontrado'
            }, status=404)
        
        # Obtener contraseñas del vault
        passwords = PasswordEntry.objects.filter(user=request.user, vault=vault)
        
        passwords_data = []
        for pwd in passwords:
            passwords_data.append({
                'id': pwd.id,
                'website': pwd.website,
                'username': pwd.username,
                'encryption_algorithm': pwd.encryption_algorithm,
                'created_at': pwd.created_at.isoformat(),
                'updated_at': pwd.updated_at.isoformat()
            })
        
        return JsonResponse({
            'success': True,
            'vault': {
                'id': vault.id,
                'name': vault.name,
                'description': vault.description,
                'color': vault.color,
                'is_private': vault.is_private
            },
            'passwords': passwords_data,
            'count': len(passwords_data)
        })
        
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': 'Error obteniendo contraseñas del vault',
            'details': str(e)
        }, status=500)


@api_view(['GET'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def api_unvaulted_passwords(request):
    """API para obtener contraseñas que no están en ningún vault"""
    try:
        passwords = PasswordEntry.objects.filter(user=request.user, vault__isnull=True)
        
        passwords_data = []
        for pwd in passwords:
            passwords_data.append({
                'id': pwd.id,
                'website': pwd.website,
                'username': pwd.username,
                'encryption_algorithm': pwd.encryption_algorithm,
                'created_at': pwd.created_at.isoformat(),
                'updated_at': pwd.updated_at.isoformat()
            })
        
        return JsonResponse({
            'success': True,
            'passwords': passwords_data,
            'count': len(passwords_data)
        })
        
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': 'Error obteniendo contraseñas sin vault',
            'details': str(e)
        }, status=500)


@api_view(['POST'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def api_move_password_to_vault(request):
    """API para mover una contraseña a un vault diferente"""
    try:
        data = json.loads(request.body)
        password_id = data.get('password_id')
        vault_id = data.get('vault_id')  # Puede ser null para remover de vault
        vault_password = data.get('vault_password', '').strip()  # Solo si el vault destino es privado
        
        if not password_id:
            return JsonResponse({
                'success': False,
                'error': 'ID de contraseña requerido'
            }, status=400)
        
        # Obtener la contraseña
        try:
            password_entry = PasswordEntry.objects.get(id=password_id, user=request.user)
        except PasswordEntry.DoesNotExist:
            return JsonResponse({
                'success': False,
                'error': 'Contraseña no encontrada'
            }, status=404)
        
        # Determinar vault destino
        destination_vault = None
        if vault_id:
            try:
                destination_vault = Vault.objects.get(id=vault_id, user=request.user)
                
                # Si el vault destino es privado, verificar contraseña
                if destination_vault.is_private:
                    if not vault_password:
                        return JsonResponse({
                            'success': False,
                            'error': 'Contraseña del vault requerida'
                        }, status=400)
                    
                    if not destination_vault.verify_vault_password(vault_password):
                        return JsonResponse({
                            'success': False,
                            'error': 'Contraseña del vault incorrecta'
                        }, status=400)
                
            except Vault.DoesNotExist:
                return JsonResponse({
                    'success': False,
                    'error': 'Vault destino no encontrado'
                }, status=404)
        
        # Actualizar la contraseña
        old_vault_name = password_entry.vault.name if password_entry.vault else 'Sin vault'
        password_entry.vault = destination_vault
        password_entry.save()
        
        new_vault_name = destination_vault.name if destination_vault else 'Sin vault'
        
        # Log de actividad
        log_activity(
            user=request.user,
            activity_type='password_moved',
            title='Contraseña movida entre vaults',
            description=f'Contraseña de {password_entry.website} movida de "{old_vault_name}" a "{new_vault_name}"',
            severity='info'
        )
        
        return JsonResponse({
            'success': True,
            'message': f'Contraseña movida a "{new_vault_name}" exitosamente',
            'moved_from': old_vault_name,
            'moved_to': new_vault_name
        })
        
    except json.JSONDecodeError:
        return JsonResponse({
            'success': False,
            'error': 'Datos JSON inválidos'
        }, status=400)
    except Exception as e:
        print(f"Error moviendo contraseña: {e}")
        return JsonResponse({
            'success': False,
            'error': 'Error interno del servidor'
        }, status=500)     
        
        
@api_view(['POST'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def api_batch_delete_passwords(request):
    """API para eliminar múltiples contraseñas"""
    try:
        data = json.loads(request.body)
        password_ids = data.get('password_ids', [])
        master_password = data.get('master_password', '').strip()
        
        if not password_ids:
            return JsonResponse({
                'success': False,
                'error': 'Lista de IDs de contraseñas requerida'
            }, status=400)
        
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
        
        # Obtener y eliminar contraseñas
        deleted_passwords = []
        errors = []
        
        for password_id in password_ids:
            try:
                password_entry = PasswordEntry.objects.get(id=password_id, user=request.user)
                website_name = password_entry.website
                password_entry.delete()
                deleted_passwords.append({
                    'id': password_id,
                    'website': website_name
                })
            except PasswordEntry.DoesNotExist:
                errors.append(f'Contraseña con ID {password_id} no encontrada')
                continue
            except Exception as e:
                errors.append(f'Error eliminando contraseña {password_id}: {str(e)}')
                continue
        
        # Log de actividad
        if deleted_passwords:
            websites = ', '.join([pwd['website'] for pwd in deleted_passwords])
            log_activity(
                user=request.user,
                activity_type='batch_password_deleted',
                title='Contraseñas eliminadas en lote',
                description=f'{len(deleted_passwords)} contraseñas eliminadas: {websites}',
                severity='warning'
            )
        
        return JsonResponse({
            'success': True,
            'message': f'{len(deleted_passwords)} contraseñas eliminadas exitosamente',
            'deleted_count': len(deleted_passwords),
            'deleted_passwords': deleted_passwords,
            'errors': errors
        })
        
    except json.JSONDecodeError:
        return JsonResponse({
            'success': False,
            'error': 'Datos JSON inválidos'
        }, status=400)
    except Exception as e:
        print(f"Error en batch delete: {e}")
        return JsonResponse({
            'success': False,
            'error': 'Error interno del servidor'
        }, status=500)
        
@api_view(['POST'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def api_batch_move_passwords(request):
    """API para mover múltiples contraseñas a un vault"""
    try:
        data = json.loads(request.body)
        password_ids = data.get('password_ids', [])
        destination_vault_id = data.get('destination_vault_id')  # Puede ser null
        vault_password = data.get('vault_password', '').strip()
        
        if not password_ids:
            return JsonResponse({
                'success': False,
                'error': 'Lista de IDs de contraseñas requerida'
            }, status=400)
        
        # Determinar vault destino
        destination_vault = None
        if destination_vault_id:
            try:
                destination_vault = Vault.objects.get(id=destination_vault_id, user=request.user)
                
                # Si el vault destino es privado, verificar contraseña
                if destination_vault.is_private:
                    if not vault_password:
                        return JsonResponse({
                            'success': False,
                            'error': 'Contraseña del vault requerida'
                        }, status=400)
                    
                    if not destination_vault.verify_vault_password(vault_password):
                        return JsonResponse({
                            'success': False,
                            'error': 'Contraseña del vault incorrecta'
                        }, status=400)
                
            except Vault.DoesNotExist:
                return JsonResponse({
                    'success': False,
                    'error': 'Vault destino no encontrado'
                }, status=404)
        
        # Mover contraseñas
        moved_passwords = []
        errors = []
        
        for password_id in password_ids:
            try:
                password_entry = PasswordEntry.objects.get(id=password_id, user=request.user)
                old_vault_name = password_entry.vault.name if password_entry.vault else 'Sin vault'
                password_entry.vault = destination_vault
                password_entry.save()
                
                moved_passwords.append({
                    'id': password_id,
                    'website': password_entry.website,
                    'old_vault': old_vault_name,
                    'new_vault': destination_vault.name if destination_vault else 'Sin vault'
                })
            except PasswordEntry.DoesNotExist:
                errors.append(f'Contraseña con ID {password_id} no encontrada')
                continue
            except Exception as e:
                errors.append(f'Error moviendo contraseña {password_id}: {str(e)}')
                continue
        
        # Log de actividad
        if moved_passwords:
            new_vault_name = destination_vault.name if destination_vault else 'Sin vault'
            log_activity(
                user=request.user,
                activity_type='batch_password_moved',
                title='Contraseñas movidas en lote',
                description=f'{len(moved_passwords)} contraseñas movidas a "{new_vault_name}"',
                severity='info'
            )
        
        return JsonResponse({
            'success': True,
            'message': f'{len(moved_passwords)} contraseñas movidas exitosamente',
            'moved_count': len(moved_passwords),
            'moved_passwords': moved_passwords,
            'errors': errors
        })
        
    except json.JSONDecodeError:
        return JsonResponse({
            'success': False,
            'error': 'Datos JSON inválidos'
        }, status=400)
    except Exception as e:
        print(f"Error en batch move: {e}")
        return JsonResponse({
            'success': False,
            'error': 'Error interno del servidor'
        }, status=500)