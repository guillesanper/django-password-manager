from django.http import JsonResponse, HttpResponse
from rest_framework.decorators import api_view, permission_classes, authentication_classes
from ..authentication import CookieJWTAuthentication
from rest_framework.permissions import IsAuthenticated

import math
import uuid

from ..models import EncryptedFile
from ..minio_service import enhanced_minio_service
from ..utils.logging_utils import log_activity

import logging

logger = logging.getLogger(__name__)


# ==========================================
# VISTAS DE FICHEROS (Fase 2, zero-knowledge)
# ==========================================
#
# El contenido se cifra en el CLIENTE por chunks (crypto.ts::encryptFile) con una FileKey
# propia, envuelta bajo la VaultKey. El servidor recibe un blob ya opaco y sólo:
#   - lo guarda en MinIO (con la capa Fernet del sistema como cifrado at-rest; se retira en el
#     paso 28 a favor de SSE),
#   - almacena metadatos opacos: client_id + ciphertext (nombre, FileKey, tipo, tamaño... todo
#     envuelto por el cliente). title/algorithm/salt/iv quedan vacíos en v2.
#
# Consecuencias: ya no se pide la contraseña maestra (no hay descifrado en servidor), la
# descarga devuelve SIEMPRE application/octet-stream (el servidor ni conoce el nombre real →
# M4 cerrado por construcción) y los logs se registran por id (privacidad).

MAX_FILE_SIZE = 100 * 1024 * 1024  # 100 MB (sobre el blob ya cifrado)


def _valid_uuid(value):
    if not value:
        return None
    try:
        return str(uuid.UUID(str(value)))
    except (ValueError, AttributeError, TypeError):
        return None


def format_file_size(size_bytes):
    """Formatear tamaño de archivo en formato legible."""
    if not size_bytes:
        return "0 B"
    size_names = ["B", "KB", "MB", "GB", "TB"]
    i = int(math.floor(math.log(size_bytes, 1024)))
    p = math.pow(1024, i)
    s = round(size_bytes / p, 2)
    return f"{s} {size_names[i]}"


@api_view(['GET'])
@authentication_classes([CookieJWTAuthentication])
@permission_classes([IsAuthenticated])
def api_files(request):
    """Lista los ficheros del usuario como metadatos opacos. El cliente descifra `ciphertext`
    con la VaultKey para obtener nombre/tipo/FileKey."""
    try:
        files = EncryptedFile.objects.filter(user=request.user)
        data = []
        for f in files:
            info = {
                'id': f.id,
                'client_id': str(f.client_id) if f.client_id else None,
                'crypto_version': f.crypto_version,
                'ciphertext': f.ciphertext,
                'file_path': f.file_path,
                'uploaded_at': f.uploaded_at.isoformat(),
                'updated_at': f.updated_at.isoformat(),
            }
            if f.file_path:
                try:
                    minio_info = enhanced_minio_service.get_file_info(object_name=f.file_path)
                    if minio_info['success']:
                        size = minio_info['info']['size']
                        info['size'] = size
                        info['size_formatted'] = format_file_size(size)
                except Exception:
                    logger.exception("Error obteniendo info de MinIO para el fichero %s", f.id)
            data.append(info)

        return JsonResponse({'files': data})

    except Exception:
        logger.exception("Error en api_files")
        return JsonResponse({'error': 'Error obteniendo lista de archivos'}, status=500)


@api_view(['POST'])
@authentication_classes([CookieJWTAuthentication])
@permission_classes([IsAuthenticated])
def upload_file_combined(request):
    """Sube un fichero ya cifrado en cliente. Multipart: file (blob cifrado) + client_id +
    ciphertext (metadatos+FileKey envueltos). Sin contraseña maestra ni algoritmo."""
    try:
        if 'file' not in request.FILES:
            return JsonResponse({'success': False, 'error': 'No se encontró ningún archivo'}, status=400)

        uploaded_file = request.FILES['file']
        client_id = _valid_uuid(request.POST.get('client_id'))
        ciphertext = request.POST.get('ciphertext')

        if not client_id:
            return JsonResponse({'success': False, 'error': 'client_id (UUID) requerido'}, status=400)
        if not ciphertext:
            return JsonResponse({'success': False, 'error': 'ciphertext requerido'}, status=400)
        if uploaded_file.size > MAX_FILE_SIZE:
            return JsonResponse({
                'success': False,
                'error': 'El archivo es demasiado grande (máximo 100MB)',
            }, status=400)

        # El blob ya viene cifrado desde el cliente; el servidor no lo interpreta.
        encrypted_blob = uploaded_file.read()
        object_name = f"user_{request.user.id}/{uuid.uuid4()}"

        upload_result = enhanced_minio_service.upload_file(
            file_data=encrypted_blob,
            object_name=object_name,
            metadata={'user_id': str(request.user.id), 'crypto_version': '2'},
        )
        if not upload_result['success']:
            # El 'error' de minio_service trae internos de S3: al log, no al cliente (M1).
            logger.error("Fallo subiendo a MinIO: %s", upload_result.get('error'))
            return JsonResponse({'success': False, 'error': 'Error subiendo el archivo'}, status=500)

        try:
            file_entry = EncryptedFile.objects.create(
                user=request.user,
                client_id=client_id,
                ciphertext=ciphertext,
                crypto_version=2,
                file_path=object_name,
                # Columnas del esquema legado: vacías en v2.
                title='',
                algorithm='',
                salt='',
                iv_or_nonce='',
                encrypted_key='',
            )
        except Exception:
            # Si el registro en BD falla (p. ej. client_id duplicado), no dejar el objeto huérfano.
            logger.exception("Error creando EncryptedFile; limpiando objeto en MinIO")
            try:
                enhanced_minio_service.delete_file(object_name)
            except Exception:
                logger.exception("No se pudo limpiar el objeto huérfano %s", object_name)
            return JsonResponse({'success': False, 'error': 'Error registrando el archivo'}, status=400)

        log_activity(
            user=request.user,
            activity_type='file_uploaded',
            title='Archivo cifrado subido',
            description=f'Archivo subido (id {file_entry.id})',
            severity='success',
            related_obj=file_entry,
        )

        return JsonResponse({
            'success': True,
            'message': 'Archivo subido exitosamente',
            'file': {
                'id': file_entry.id,
                'client_id': str(file_entry.client_id),
                'uploaded_at': file_entry.uploaded_at.isoformat(),
                'size': uploaded_file.size,
            },
        })

    except Exception:
        logger.exception("Error en upload_file_combined")
        return JsonResponse({'success': False, 'error': 'Error interno del servidor'}, status=500)


@api_view(['POST'])
@authentication_classes([CookieJWTAuthentication])
@permission_classes([IsAuthenticated])
def download_file_combined(request, file_id):
    """Devuelve el blob cifrado (tras retirar la capa Fernet at-rest). El cliente lo descifra
    con la FileKey. Sin contraseña maestra. Siempre application/octet-stream (M4)."""
    try:
        try:
            file_entry = EncryptedFile.objects.get(id=file_id, user=request.user)
        except EncryptedFile.DoesNotExist:
            return JsonResponse({'success': False, 'error': 'Archivo no encontrado'}, status=404)

        if not file_entry.file_path:
            return JsonResponse({'success': False, 'error': 'Ruta de archivo inválida'}, status=400)

        download_result = enhanced_minio_service.download_file(file_entry.file_path)
        if not download_result['success']:
            # Frontera de confianza: el 'error' de MinIO se registra entero; al cliente, genérico (M1).
            logger.error("Fallo descargando de MinIO: %s", download_result['error'])
            return JsonResponse({'success': False, 'error': 'Error descargando archivo'}, status=500)

        encrypted_blob = download_result['data']

        log_activity(
            user=request.user,
            activity_type='file_downloaded',
            title='Archivo descargado',
            description=f'Archivo descargado (id {file_entry.id})',
            severity='info',
        )

        response = HttpResponse(encrypted_blob, content_type='application/octet-stream')
        # El nombre real va cifrado en `ciphertext`; el cliente lo pone tras descifrar.
        response['Content-Disposition'] = 'attachment; filename="download.bin"'
        response['Content-Length'] = len(encrypted_blob)
        response['X-Content-Type-Options'] = 'nosniff'
        response['Cache-Control'] = 'no-store'
        return response

    except Exception:
        logger.exception("Error general en download_file_combined")
        return JsonResponse({'success': False, 'error': 'Error interno del servidor'}, status=500)


@api_view(['POST'])
@authentication_classes([CookieJWTAuthentication])
@permission_classes([IsAuthenticated])
def delete_file_combined(request, file_id):
    """Elimina un fichero (MinIO + BD). Autorizado por la sesión; sin contraseña maestra."""
    try:
        try:
            file_entry = EncryptedFile.objects.get(id=file_id, user=request.user)
        except EncryptedFile.DoesNotExist:
            return JsonResponse({'success': False, 'error': 'Archivo no encontrado'}, status=404)

        if file_entry.file_path:
            result = enhanced_minio_service.delete_file(file_entry.file_path)
            error_msg = (result.get('error') or '').lower()
            if not result['success'] and 'not found' not in error_msg and 'nosuchkey' not in error_msg:
                logger.error("Fallo eliminando de MinIO: %s", result.get('error'))
                return JsonResponse({
                    'success': False,
                    'error': 'Error eliminando el archivo del almacenamiento',
                }, status=500)

        file_id_ref = file_entry.id
        file_entry.delete()

        log_activity(
            user=request.user,
            activity_type='file_deleted',
            title='Archivo eliminado',
            description=f'Archivo eliminado (id {file_id_ref})',
            severity='warning',
        )

        return JsonResponse({'success': True, 'message': 'Archivo eliminado exitosamente'})

    except Exception:
        logger.exception("Error general eliminando archivo")
        return JsonResponse({'success': False, 'error': 'Error interno del servidor'}, status=500)


@api_view(['POST'])
@authentication_classes([CookieJWTAuthentication])
@permission_classes([IsAuthenticated])
def delete_all_files_combined(request):
    """Elimina todos los ficheros del usuario (MinIO por prefijo + BD). Sin contraseña maestra."""
    try:
        user_files = EncryptedFile.objects.filter(user=request.user)
        total_files = user_files.count()
        if total_files == 0:
            return JsonResponse({
                'success': True,
                'message': 'No hay archivos para eliminar',
                'stats': {'deleted_count': 0, 'error_count': 0},
            })

        # Borrado masivo en MinIO por prefijo user_{id}/.
        minio_result = enhanced_minio_service.delete_user_files(request.user.id)
        if not minio_result['success']:
            logger.error("Errores en borrado masivo de MinIO: %s", minio_result.get('errors'))

        deleted_count, _ = user_files.delete()

        log_activity(
            user=request.user,
            activity_type='file_deleted',
            title='Eliminación masiva de archivos',
            description=f'{total_files} archivos eliminados',
            severity='warning',
        )

        return JsonResponse({
            'success': True,
            'message': f'{total_files} archivos eliminados',
            'stats': {'total_files': total_files, 'deleted_count': total_files, 'error_count': 0},
        })

    except Exception:
        logger.exception("Error eliminando todos los archivos")
        return JsonResponse({'success': False, 'error': 'Error interno del servidor'}, status=500)
