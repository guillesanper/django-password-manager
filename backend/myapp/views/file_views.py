from django.http import JsonResponse, HttpResponse
from rest_framework.decorators import api_view, permission_classes,authentication_classes
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.permissions import IsAuthenticated
from django.utils import timezone
from datetime import timedelta
from collections import Counter


import json
import math
import uuid
import io
import re
import urllib.parse


from ..models import EncryptedFile,MasterKey
from ..minio_service import enhanced_minio_service
from ..utils.logging_utils import log_activity
from ..encryption_utils import encrypt_file_data,decrypt_file_data



@api_view(['GET'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def api_files(request):
    """API para obtener archivos del usuario con información de MinIO"""
    try:
        files = EncryptedFile.objects.filter(user=request.user)
        
        # Obtener información adicional de MinIO si es necesario
        
        data = []
        for file in files:
            try:
                # Información básica de la base de datos
                file_info = {
                    'id': file.id,
                    'title': file.title,
                    'algorithm': file.algorithm,
                    'uploaded_at': file.uploaded_at.isoformat(),
                    'updated_at': file.updated_at.isoformat(),
                    'encrypted_key': file.encrypted_key,
                    'salt': file.salt,
                    'iv_or_nonce': file.iv_or_nonce,
                    'file_path': file.file_path
                }
                
                # Obtener información adicional de MinIO
                if file.file_path:
                    object_name = file.file_path
                    minio_info = enhanced_minio_service.get_file_info(
                        object_name=object_name,
                        user_id=request.user.id
                    )
                    
                    if minio_info['success']:
                        file_info.update({
                            'size': minio_info['info']['size'],
                            'size_formatted': format_file_size(minio_info['info']['size']),
                            'minio_last_modified': minio_info['info'].get('last_modified'),
                            'etag': minio_info['info'].get('etag'),
                            'encryption_metadata': minio_info['info'].get('metadata', {})
                        })
                
                data.append(file_info)
                
            except Exception as e:
                error_msg = str(e)
                file_data = {
                    'id': file.id,
                    'title': file.title,
                    'algorithm': file.algorithm,
                    'uploaded_at': file.uploaded_at.isoformat(),
                    'updated_at': file.updated_at.isoformat(),
                    'file_path': file.file_path
                }
                
                # Solo agregar error si es un error real (no solo falta de metadata)
                if 'NoSuchKey' in error_msg or 'not found' in error_msg.lower():
                    file_data['minio_error'] = 'Archivo no encontrado en almacenamiento'
                # Para otros errores menores, no mostrar advertencia
                
                data.append(file_data)
        
        return JsonResponse({'files': data})
        
    except Exception as e:
        return JsonResponse({
            'error': 'Error obteniendo lista de archivos',
            'details': str(e)
        }, status=500)
        
        

@api_view(['GET'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def upload_file_combined(request):
    """
    Subir archivo con doble encriptación (encryption_utils + Fernet) 
    usando manejo robusto de respuestas
    """
    try:
        # Verificar que se envió un archivo
        if 'file' not in request.FILES:
            return JsonResponse({
                'success': False,
                'error': 'No se encontró ningún archivo'
            }, status=400)
        
        uploaded_file = request.FILES['file']
        algorithm = request.POST.get('algorithm', 'AES')
        master_password = request.POST.get('master_password', '').strip()
        
        # Validaciones básicas
        if not master_password:
            return JsonResponse({
                'success': False,
                'error': 'Master password requerida'
            }, status=400)
        
        if algorithm not in ['AES', 'ChaCha20']:
            return JsonResponse({
                'success': False,
                'error': 'Algoritmo de encriptación inválido'
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
        
        # Validar tamaño del archivo (máximo 100MB)
        max_size = 100 * 1024 * 1024  # 100MB
        if uploaded_file.size > max_size:
            return JsonResponse({
                'success': False,
                'error': 'El archivo es demasiado grande (máximo 100MB)'
            }, status=400)
        
        # PASO 1: Leer archivo completo en memoria
        file_data = uploaded_file.read()
        print(f"[DEBUG] Archivo original: {len(file_data)} bytes")
        
        # PASO 2: Primera capa - Encriptar con encryption_utils
        master_key = master_key_entry.hashed_key.encode() if isinstance(master_key_entry.hashed_key, str) else master_key_entry.hashed_key
                
        first_layer_encrypted, encrypted_file_key, iv_or_nonce, entry_salt = encrypt_file_data(
            file_data=file_data,
            master_key=master_key,
            algorithm=algorithm
        )
        
        print(f"[DEBUG] Primera capa encriptada: {len(first_layer_encrypted)} bytes")
        
        # PASO 3: Segunda capa - Encriptar con Fernet (sistema)
        final_encrypted_data = enhanced_minio_service.system_fernet.encrypt(first_layer_encrypted)
        
        print(f"[DEBUG] Segunda capa encriptada: {len(final_encrypted_data)} bytes")
        
        # PASO 4: Preparar para subida a MinIO
        unique_filename = f"{uuid.uuid4()}_{uploaded_file.name}"
        object_name = f"user_{request.user.id}/{unique_filename}"
        
        # Metadatos del archivo
        metadata = {
            'user_id': str(request.user.id),
            'encryption_algorithm': algorithm,
            'double_encrypted': 'True',
            'user_salt': entry_salt,
            'upload_timestamp': timezone.now().isoformat(),
            'original_filename': uploaded_file.name,
            'file_size': str(uploaded_file.size),
            'iv_or_nonce': iv_or_nonce
        }
        
        # PASO 5: Subir a MinIO
        file_stream = io.BytesIO(final_encrypted_data)
        
        result = enhanced_minio_service.client.put_object(
            enhanced_minio_service.bucket_name,
            object_name,
            file_stream,
            len(final_encrypted_data),
            content_type='application/octet-stream',
            metadata=metadata
        )
        
        print(f"[DEBUG] Subido a MinIO: {object_name}")
        
        # PASO 6: Crear registro en la base de datos
        file_entry = EncryptedFile.objects.create(
            user=request.user,
            title=uploaded_file.name,  # Usar nombre sanitizado
            algorithm=algorithm,
            salt=entry_salt,
            iv_or_nonce=iv_or_nonce,
            encrypted_key=encrypted_file_key,
            file_path=object_name
        )
        
        # PASO 7: Log de actividad
        log_activity(
            user=request.user,
            activity_type='file_uploaded',
            title='Archivo encriptado subido (Doble Encriptación)',
            description=f'Archivo {uploaded_file.name} encriptado con {algorithm} + Fernet',
            severity='success',
            related_obj=file_entry
        )
        
        return JsonResponse({
            'success': True,
            'message': 'Archivo subido exitosamente con doble encriptación',
            'file': {
                'id': file_entry.id,
                'title': file_entry.title,
                'algorithm': f'{file_entry.algorithm} + Fernet',
                'uploaded_at': file_entry.uploaded_at.isoformat(),
                'size': uploaded_file.size,
                'encryption_layers': 2
            }
        })
        
    except Exception as e:
        print(f"[ERROR] Error en upload_file_combined: {e}")
        import traceback
        traceback.print_exc()
        return JsonResponse({
            'success': False,
            'error': f'Error interno del servidor: {str(e)}'
        }, status=500)


@api_view(['POST'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def download_file_combined(request, file_id):
    """
    Descargar archivo con doble desencriptación (Fernet + encryption_utils)
    usando manejo robusto de respuestas
    """
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
        
        # Obtener registro del archivo
        try:
            file_entry = EncryptedFile.objects.get(id=file_id, user=request.user)
        except EncryptedFile.DoesNotExist:
            return JsonResponse({
                'success': False,
                'error': 'Archivo no encontrado'
            }, status=404)
        
        # PASO 1: Descargar de MinIO
        
        try:
            # Usar método que descarga y desencripta segunda capa automáticamente
            download_result = enhanced_minio_service.download_file(file_entry.file_path)
            
            if not download_result['success']:
                return JsonResponse({
                    'success': False,
                    'error': download_result['error']
                }, status=500)
            
            first_layer_encrypted = download_result['data']
            print(f"[DEBUG] Descargado y primera desencriptación: {len(first_layer_encrypted)} bytes")
            
        except Exception as e:
            print(f"[ERROR] Error descargando de MinIO: {e}")
            return JsonResponse({
                'success': False,
                'error': f'Error descargando archivo: {str(e)}'
            }, status=500)
        
        # PASO 2: Segunda desencriptación con encryption_utils
        try:
            master_key = master_key_entry.hashed_key.encode() if isinstance(master_key_entry.hashed_key, str) else master_key_entry.hashed_key
            
            print(f"[DEBUG] Desencriptando segunda capa con:")
            print(f"  - Algorithm: {file_entry.algorithm}")
            print(f"  - Salt length: {len(file_entry.salt)}")
            print(f"  - IV/Nonce length: {len(file_entry.iv_or_nonce)}")
            print(f"  - Encrypted key length: {len(file_entry.encrypted_key)}")
            
            
            decrypted_data = decrypt_file_data(
                encrypted_data=first_layer_encrypted,
                master_key=master_key,
                encrypted_file_key=file_entry.encrypted_key,
                iv_or_nonce=file_entry.iv_or_nonce,
                entry_salt=file_entry.salt,
                algorithm=file_entry.algorithm
            )
            
            print(f"[DEBUG] Archivo completamente desencriptado: {len(decrypted_data)} bytes")
            
            # Verificar que los datos son bytes
            if not isinstance(decrypted_data, bytes):
                print(f"[WARNING] Datos no son bytes, convirtiendo...")
                if isinstance(decrypted_data, str):
                    decrypted_data = decrypted_data.encode('utf-8')
                else:
                    decrypted_data = bytes(decrypted_data)
            
        except Exception as decrypt_error:
            print(f"[ERROR] Error en desencriptación: {decrypt_error}")
            import traceback
            traceback.print_exc()
            return JsonResponse({
                'success': False,
                'error': f'Error desencriptando archivo: {str(decrypt_error)}'
            }, status=500)
        
        # PASO 3: Log de actividad
        log_activity(
            user=request.user,
            activity_type='file_downloaded',
            title='Archivo descargado (Doble Desencriptación)',
            description=f'Archivo {file_entry.title} descargado y desencriptado completamente',
            severity='info'
        )
        
        # PASO 4: Determinar content-type y crear respuesta
        content_type = get_content_type_from_filename(file_entry.title)
        
        return create_download_response(
            file_data=decrypted_data,
            filename=file_entry.title,
            content_type=content_type
        )
            
    except json.JSONDecodeError:
        return JsonResponse({
            'success': False,
            'error': 'Datos JSON inválidos'
        }, status=400)
    except Exception as e:
        print(f"[ERROR] Error general en download_file_combined: {e}")
        import traceback
        traceback.print_exc()
        return JsonResponse({
            'success': False,
            'error': f'Error interno del servidor: {str(e)}'
        }, status=500)


@api_view(['POST'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def delete_file_combined(request, file_id):
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
        
        # Obtener registro del archivo
        try:
            file_entry = EncryptedFile.objects.get(id=file_id, user=request.user)
        except EncryptedFile.DoesNotExist:
            return JsonResponse({
                'success': False,
                'error': 'Archivo no encontrado'
            }, status=404)
        
        # DEBUG: Verificar datos antes de eliminar
        print(f"[DEBUG] Eliminando archivo:")
        print(f"  - ID: {file_entry.id}")
        print(f"  - Title: {file_entry.title}")
        print(f"  - File path: '{file_entry.file_path}'")
        print(f"  - User ID: {request.user.id}")
        
        # Verificar que file_path no esté vacío
        if not file_entry.file_path:
            print(f"[ERROR] file_path está vacío para archivo ID {file_id}")
            return JsonResponse({
                'success': False,
                'error': 'Ruta de archivo inválida'
            }, status=400)
        
        # Eliminar de MinIO con debug mejorado
        
        print(f"[DEBUG] Llamando enhanced_minio_service.delete_file('{file_entry.file_path}')")
        
        try:
            result = enhanced_minio_service.delete_file(file_entry.file_path)
            
            print(f"[DEBUG] Resultado de MinIO: {result}")
            
            if not result['success']:
                error_msg = result.get('error', 'Error desconocido')
                print(f"[ERROR] MinIO delete failed: {error_msg}")
                
                # Solo continuar si el archivo ya no existe
                if ('not found' in error_msg.lower() or 
                    'NoSuchKey' in error_msg or 
                    'nosuchkey' in error_msg.lower()):
                    print(f"[INFO] Archivo ya no existe en MinIO, continuando...")
                else:
                    return JsonResponse({
                        'success': False,
                        'error': f'Error eliminando de almacenamiento: {error_msg}'
                    }, status=500)
            else:
                print(f"[SUCCESS] Archivo eliminado de MinIO exitosamente")
                
        except Exception as e:
            print(f"[ERROR] Excepción eliminando de MinIO: {e}")
            import traceback
            traceback.print_exc()
            
            # Solo continuar si es error de archivo no encontrado
            if 'not found' not in str(e).lower():
                return JsonResponse({
                    'success': False,
                    'error': f'Error eliminando de almacenamiento: {str(e)}'
                }, status=500)
        
        # Si llegamos aquí, proceder a eliminar de BD
        filename = file_entry.title
        file_entry.delete()
        
        print(f"[SUCCESS] Archivo eliminado de BD: {filename}")
        
        # Log de actividad
        log_activity(
            user=request.user,
            activity_type='file_deleted',
            title='Archivo eliminado',
            description=f'Archivo {filename} eliminado permanentemente',
            severity='warning'
        )
        
        return JsonResponse({
            'success': True,
            'message': f'Archivo "{filename}" eliminado exitosamente'
        })
        
    except Exception as e:
        print(f"[ERROR] Error general eliminando archivo: {e}")
        import traceback
        traceback.print_exc()
        return JsonResponse({
            'success': False,
            'error': f'Error interno del servidor: {str(e)}'
        }, status=500)


@api_view(['POST'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def delete_all_files_combined(request):
    """
    Eliminar todos los archivos del usuario con manejo robusto mejorado
    """
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
        
        # Obtener todos los archivos del usuario
        user_files = EncryptedFile.objects.filter(user=request.user)
        
        if not user_files.exists():
            return JsonResponse({
                'success': True,
                'message': 'No hay archivos para eliminar',
                'stats': {
                    'deleted_count': 0,
                    'error_count': 0
                }
            })
        
        deleted_count = 0
        errors = []
        total_files = user_files.count()
        
        # Eliminar cada archivo
        
        for file_entry in user_files:
            try:
                # Eliminar de MinIO
                result = enhanced_minio_service.delete_file(file_entry.file_path)
                
                if result['success'] or 'not found' in result.get('error', '').lower():
                    # Eliminar de BD si MinIO fue exitoso o archivo ya no existe
                    file_entry.delete()
                    deleted_count += 1
                    print(f"[DEBUG] Eliminado: {file_entry.title}")
                else:
                    errors.append({
                        'file': file_entry.title,
                        'error': result.get('error', 'Error desconocido')
                    })
                
            except Exception as e:
                error_msg = f"Error eliminando {file_entry.title}: {str(e)}"
                print(f"[ERROR] {error_msg}")
                errors.append({
                    'file': file_entry.title,
                    'error': str(e)
                })
        
        # Log de actividad
        log_activity(
            user=request.user,
            activity_type='file_deleted',
            title='Eliminación masiva de archivos',
            description=f'{deleted_count}/{total_files} archivos eliminados. {len(errors)} errores.',
            severity='warning' if errors else 'success'
        )
        
        # Preparar respuesta
        response_data = {
            'success': deleted_count > 0,
            'message': f'{deleted_count} de {total_files} archivos eliminados',
            'stats': {
                'total_files': total_files,
                'deleted_count': deleted_count,
                'error_count': len(errors)
            }
        }
        
        if errors:
            response_data['errors'] = errors
            response_data['partial_success'] = True
            
        # Status code apropiado
        status_code = 200 if not errors else 207  # 207 Multi-Status para éxito parcial
        
        return JsonResponse(response_data, status=status_code)
        
    except json.JSONDecodeError:
        return JsonResponse({
            'success': False,
            'error': 'Datos JSON inválidos'
        }, status=400)
    except Exception as e:
        print(f"[ERROR] Error eliminando todos los archivos: {e}")
        import traceback
        traceback.print_exc()
        return JsonResponse({
            'success': False,
            'error': f'Error interno del servidor: {str(e)}'
        }, status=500)
        


@api_view(['GET'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def api_files_stats_combined(request):
    """API para estadísticas detalladas incluyendo tipos de encriptación"""
    try:
        user_files = EncryptedFile.objects.filter(user=request.user)
        
        if not user_files.exists():
            return JsonResponse({
                'success': True,
                'stats': {
                    'total_files': 0,
                    'total_size': 0,
                    'encryption_types': {},
                    'algorithms_used': [],
                    'recent_uploads': 0
                }
            })
                
        total_size = 0
        algorithms = []
        encryption_types = {'single': 0, 'double': 0}
        successful_reads = 0
        
        for file in user_files:
            algorithms.append(file.algorithm)
            
            # Detectar tipo de encriptación
            enc_type = detect_encryption_type(file)
            encryption_types[enc_type] += 1
            
            try:
                info_result = enhanced_minio_service.get_file_info(file.file_path)
                
                if info_result['success']:
                    total_size += info_result['info']['size']
                    successful_reads += 1
                    
            except Exception:
                continue
        
        # Archivos recientes (últimos 7 días)
        recent_uploads = user_files.filter(
            uploaded_at__gte=timezone.now() - timedelta(days=7)
        ).count()
        
        return JsonResponse({
            'success': True,
            'stats': {
                'total_files': user_files.count(),
                'total_size': total_size,
                'total_size_formatted': format_file_size(total_size),
                'encryption_types': encryption_types,
                'algorithms_used': list(set(algorithms)),
                'recent_uploads': recent_uploads,
                'sync_success_rate': f"{(successful_reads/user_files.count()*100):.1f}%" if user_files.count() > 0 else "0%",
                'algorithm_distribution': dict(Counter(algorithms))
            }
        })
        
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': 'Error obteniendo estadísticas',
            'details': str(e)
        }, status=500)



def detect_encryption_type(file_entry):
    """
    Detecta el tipo de encriptación basado en los metadatos del archivo
    """
    try:
        
        # Intentar obtener metadatos de MinIO
        info_result = enhanced_minio_service.get_file_info(file_entry.file_path)
        
        if info_result['success']:
            metadata = info_result['info'].get('metadata', {})
            
            # Verificar indicadores de doble encriptación
            if metadata.get('double_encrypted') == 'True':
                return 'double'
            elif metadata.get('simple_encryption') == 'True':
                return 'fernet'
            elif file_entry.algorithm == 'Fernet':
                return 'fernet'
            elif metadata.get('single_encrypted') == 'True':
                return 'single'
        
        # Fallback basado en datos del modelo
        if file_entry.algorithm == 'Fernet':
            return 'fernet'
        elif file_entry.encrypted_key == 'fernet_key_derived':
            return 'fernet'
        else:
            return 'single'  # Asumir encriptación simple por defecto
            
    except Exception as e:
        print(f"[WARNING] Error detectando tipo de encriptación: {e}")
        # Fallback seguro
        return 'single' if file_entry.algorithm != 'Fernet' else 'fernet'


# ==========================================
# API PARA ESTADÍSTICAS DE ARCHIVOS
# ==========================================

@api_view(['GET'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def api_files_stats(request):
    """API para estadísticas de archivos del usuario"""
    try:
        user_files = EncryptedFile.objects.filter(user=request.user)
        
        if not user_files.exists():
            return JsonResponse({
                'success': True,
                'stats': {
                    'total_files': 0,
                    'total_size': 0,
                    'algorithms_used': [],
                    'recent_uploads': 0
                }
            })
        
        # Obtener información de MinIO para calcular tamaños
        
        total_size = 0
        algorithms = []
        successful_reads = 0
        
        for file in user_files:
            algorithms.append(file.algorithm)
            
            try:
                object_name = file.file_path
                minio_info = enhanced_minio_service.get_file_info(
                    object_name=object_name,
                    user_id=request.user.id
                )
                
                if minio_info['success']:
                    total_size += minio_info['info']['size']
                    successful_reads += 1
                    
            except Exception:
                # Ignorar errores individuales
                continue
        
        # Archivos recientes (últimos 7 días)
        recent_uploads = user_files.filter(
            uploaded_at__gte=timezone.now() - timedelta(days=7)
        ).count()
        
        return JsonResponse({
            'success': True,
            'stats': {
                'total_files': user_files.count(),
                'total_size': total_size,
                'total_size_formatted': format_file_size(total_size),
                'algorithms_used': list(set(algorithms)),
                'recent_uploads': recent_uploads,
                'minio_sync_success': successful_reads,
                'algorithm_distribution': dict(Counter(algorithms))
            }
        })
        
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': 'Error obteniendo estadísticas',
            'details': str(e)
        }, status=500)
        
        

# ==========================================
# FUNCIONES AUXILIARES
# ==========================================

def get_content_type_from_filename(filename):
    """
    Obtiene el content-type basado en la extensión del archivo - MEJORADA
    """
    import mimetypes
    
    if not filename:
        return 'application/octet-stream'
    
    # Intentar primero con mimetypes
    content_type, encoding = mimetypes.guess_type(filename)
    
    if content_type:
        return content_type
    
    # Fallbacks para extensiones comunes
    extension = filename.lower().split('.')[-1] if '.' in filename else ''
    
    mime_types = {
        # Documentos
        'pdf': 'application/pdf',
        'doc': 'application/msword',
        'docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'txt': 'text/plain; charset=utf-8',
        'rtf': 'application/rtf',
        
        # Hojas de cálculo
        'xls': 'application/vnd.ms-excel',
        'xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        'csv': 'text/csv; charset=utf-8',
        
        # Presentaciones
        'ppt': 'application/vnd.ms-powerpoint',
        'pptx': 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
        
        # Imágenes
        'jpg': 'image/jpeg', 'jpeg': 'image/jpeg',
        'png': 'image/png',
        'gif': 'image/gif',
        'svg': 'image/svg+xml',
        'webp': 'image/webp',
        'bmp': 'image/bmp',
        'tiff': 'image/tiff', 'tif': 'image/tiff',
        
        # Audio
        'mp3': 'audio/mpeg',
        'wav': 'audio/wav',
        'm4a': 'audio/mp4',
        'ogg': 'audio/ogg',
        'flac': 'audio/flac',
        
        # Video
        'mp4': 'video/mp4',
        'avi': 'video/x-msvideo',
        'mov': 'video/quicktime',
        'webm': 'video/webm',
        'mkv': 'video/x-matroska',
        
        # Archivos comprimidos
        'zip': 'application/zip',
        'rar': 'application/x-rar-compressed',
        '7z': 'application/x-7z-compressed',
        'tar': 'application/x-tar',
        'gz': 'application/gzip',
        
        # Código y texto
        'js': 'application/javascript',
        'json': 'application/json',
        'xml': 'application/xml',
        'html': 'text/html; charset=utf-8',
        'css': 'text/css; charset=utf-8',
        'py': 'text/x-python; charset=utf-8',
        'java': 'text/x-java; charset=utf-8',
        'cpp': 'text/x-c++; charset=utf-8',
        'c': 'text/x-c; charset=utf-8'
    }
    
    return mime_types.get(extension, 'application/octet-stream')



def format_file_size(size_bytes):
    """Formatear tamaño de archivo en formato legible"""
    if size_bytes == 0:
        return "0 B"
    
    size_names = ["B", "KB", "MB", "GB", "TB"]
    i = int(math.floor(math.log(size_bytes, 1024)))
    p = math.pow(1024, i)
    s = round(size_bytes / p, 2)
    
    return f"{s} {size_names[i]}"

def create_download_response(file_data, filename, content_type='application/octet-stream'):
    """
    Crea una respuesta HTTP correcta para descarga de archivos - FILENAME CON COMILLAS
    """
    # Verificar que file_data es bytes
    if isinstance(file_data, str):
        file_data = file_data.encode('utf-8')
    
    # Crear respuesta con content_type correcto
    response = HttpResponse(file_data, content_type=content_type)
    
    # Sanitizar nombre
    safe_filename = sanitize_filename_for_download(filename)
    
    # CORRECCIÓN CRÍTICA: Siempre usar comillas para filenames
    try:
        # Intentar codificar como ASCII
        safe_filename.encode('ascii')
        # CAMBIO: SIEMPRE usar comillas, incluso para ASCII
        response['Content-Disposition'] = f'attachment; filename="{safe_filename}"'
        print(f"[DEBUG] Content-Disposition ASCII: attachment; filename=\"{safe_filename}\"")
    except UnicodeEncodeError:
        # Para caracteres no-ASCII, usar ambos métodos
        encoded_filename = urllib.parse.quote(safe_filename.encode('utf-8'))
        ascii_fallback = re.sub(r'[^\x20-\x7E]', '_', safe_filename)
        response['Content-Disposition'] = (
            f"attachment; "
            f"filename*=UTF-8''{encoded_filename}; "
            f'filename="{ascii_fallback}"'  # CAMBIO: Comillas aquí también
        )
        print(f"[DEBUG] Content-Disposition UTF-8: filename*=UTF-8''{encoded_filename}; filename=\"{ascii_fallback}\"")
    
    # Headers adicionales
    response['Content-Length'] = len(file_data)
    response['Content-Type'] = content_type
    response['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response['Pragma'] = 'no-cache'
    response['Expires'] = '0'
    
    print(f"[DEBUG] Preparando descarga: {safe_filename}, {len(file_data)} bytes")
    print(f"[DEBUG] Content-Disposition final: {response['Content-Disposition']}")
    print(f"[DEBUG] Content-Type: {content_type}")
    
    return response



def sanitize_filename_for_download(filename):
    """
    Sanitiza y formatea correctamente el nombre del archivo para descarga
    """
    if not filename:
        return "archivo_descargado"
    
    # Limpiar caracteres problemáticos pero mantener la extensión
    # Remover caracteres peligrosos pero preservar espacios, puntos, guiones
    sanitized = re.sub(r'[<>:"/\\|?*\x00-\x1f]', '_', filename)
    
    # Asegurar que no esté vacío después de sanitizar
    if not sanitized.strip():
        return "archivo_descargado"
    
    return sanitized.strip()