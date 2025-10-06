from django.http import JsonResponse
from rest_framework.decorators import api_view, permission_classes,authentication_classes
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.permissions import IsAuthenticated
from django.utils import timezone

from collections import Counter
import json
from datetime import timedelta
import math
import hashlib
import requests
import re

from ..models import PasswordEntry, MasterKey
from ..encryption_utils import decrypt_password


@api_view(['GET'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def api_security_analysis(request):
    """
    Análisis completo de seguridad de todas las contraseñas del usuario
    """
    try:
        # Obtener todas las contraseñas del usuario
        password_entries = PasswordEntry.objects.filter(user=request.user)
        
        if not password_entries.exists():
            return JsonResponse({
                'success': True,
                'total_passwords': 0,
                'analysis': {
                    'overall_score': 100,
                    'strength_distribution': {},
                    'security_issues': [],
                    'recommendations': ['Agrega algunas contraseñas para comenzar el análisis de seguridad']
                }
            })
        
        # Obtener master key para desencriptar
        try:
            master_key_entry = MasterKey.objects.get(user=request.user)
        except MasterKey.DoesNotExist:
            return JsonResponse({
                'success': False,
                'error': 'No se encontró la clave maestra'
            }, status=400)
        
        # Desencriptar y analizar cada contraseña
        password_analyses = []
        decrypted_passwords = []
        
        for entry in password_entries:
            try:
                decrypted_password = decrypt_password(
                    entry.encrypted_password,
                    entry.encrypted_key,
                    entry.iv_or_nonce,
                    master_key_entry.hashed_key.encode(),
                    entry.salt,
                    entry.encryption_algorithm
                ).decode('utf-8')
                
                # Calcular entropía
                entropy = calculate_password_entropy(decrypted_password)
                strength = get_password_strength_category(entropy)
                
                # Verificar en HaveIBeenPwned (esto es síncrono por simplicidad)
                breach_info = check_password_breach_sync(decrypted_password)
                
                analysis = {
                    'id': entry.id,
                    'website': entry.website,
                    'username': entry.username,
                    'entropy': round(entropy, 2),
                    'strength': strength,
                    'breach_info': breach_info,
                    'age_days': (timezone.now() - entry.created_at).days,
                    'last_updated_days': (timezone.now() - entry.updated_at).days
                }
                
                password_analyses.append(analysis)
                decrypted_passwords.append({
                    'password': decrypted_password,
                    'website': entry.website,
                    'id': entry.id
                })
                
            except Exception as e:
                # Si no se puede desencriptar una contraseña, la omitimos
                continue
        
        # Análisis agregado
        if not password_analyses:
            return JsonResponse({
                'success': False,
                'error': 'No se pudieron analizar las contraseñas'
            }, status=500)
        
        # Distribución de fortaleza
        strength_distribution = Counter()
        total_entropy = 0
        breached_count = 0
        old_passwords = 0
        weak_passwords = 0
        
        for analysis in password_analyses:
            strength_distribution[analysis['strength']['level']] += 1
            total_entropy += analysis['entropy']
            
            if analysis['breach_info']['is_breached']:
                breached_count += 1
            
            if analysis['age_days'] > 365:  # Más de 1 año
                old_passwords += 1
                
            if analysis['strength']['level'] in ['weak', 'very_weak']:
                weak_passwords += 1
        
        # Encontrar duplicados
        duplicates = find_duplicate_passwords(decrypted_passwords)
        
        # Patrones
        patterns = analyze_password_patterns(decrypted_passwords)
        
        # Calcular score general
        total_passwords = len(password_analyses)
        avg_entropy = total_entropy / total_passwords
        
        # Score basado en múltiples factores
        entropy_score = min(100, (avg_entropy / 60) * 40)  # 40% del score
        breach_score = ((total_passwords - breached_count) / total_passwords) * 30  # 30% del score
        age_score = ((total_passwords - old_passwords) / total_passwords) * 20  # 20% del score
        strength_score = ((total_passwords - weak_passwords) / total_passwords) * 10  # 10% del score
        
        overall_score = round(entropy_score + breach_score + age_score + strength_score)
        
        # Generar recomendaciones
        recommendations = []
        security_issues = []
        
        if weak_passwords > 0:
            security_issues.append({
                'type': 'weak_passwords',
                'count': weak_passwords,
                'severity': 'high',
                'message': f'{weak_passwords} contraseñas son débiles o muy débiles'
            })
            recommendations.append(f'Actualiza {weak_passwords} contraseñas débiles por otras más seguras')
        
        if breached_count > 0:
            security_issues.append({
                'type': 'breached_passwords',
                'count': breached_count,
                'severity': 'critical',
                'message': f'{breached_count} contraseñas encontradas en filtraciones de datos'
            })
            recommendations.append(f'Cambia inmediatamente {breached_count} contraseñas comprometidas')
        
        if len(duplicates) > 0:
            duplicate_count = sum(len(group) for group in duplicates.values())
            security_issues.append({
                'type': 'duplicate_passwords',
                'count': len(duplicates),
                'severity': 'medium',
                'message': f'{duplicate_count} contraseñas duplicadas encontradas'
            })
            recommendations.append('Usa contraseñas únicas para cada cuenta')
        
        if old_passwords > 0:
            security_issues.append({
                'type': 'old_passwords',
                'count': old_passwords,
                'severity': 'medium',
                'message': f'{old_passwords} contraseñas tienen más de 1 año'
            })
            recommendations.append('Actualiza contraseñas antiguas regularmente')
        
        if not recommendations:
            recommendations.append('¡Excelente! Tu seguridad de contraseñas está en buen estado')
        
        return JsonResponse({
            'success': True,
            'total_passwords': total_passwords,
            'analysis': {
                'overall_score': overall_score,
                'average_entropy': round(avg_entropy, 2),
                'strength_distribution': dict(strength_distribution),
                'security_issues': security_issues,
                'recommendations': recommendations,
                'patterns': {
                    'duplicate_groups': len(duplicates),
                    'length_distribution': dict(patterns['length_distribution']),
                    'character_usage_stats': patterns['character_usage']
                }
            },
            'passwords': password_analyses
        })
        
    except Exception as e:
        print(f"Error en análisis de seguridad: {e}")
        return JsonResponse({
            'success': False,
            'error': 'Error interno al analizar la seguridad'
        }, status=500)

@api_view(['POST'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def api_check_single_password_breach(request):
    """
    Verificar una contraseña específica contra HaveIBeenPwned
    """
    try:
        data = json.loads(request.body)
        password_id = data.get('password_id')
        master_password = data.get('master_password')
        
        if not password_id or not master_password:
            return JsonResponse({
                'success': False,
                'error': 'ID de contraseña y master password requeridos'
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
        
        # Obtener y desencriptar la contraseña
        try:
            password_entry = PasswordEntry.objects.get(id=password_id, user=request.user)
            decrypted_password = decrypt_password(
                password_entry.encrypted_password,
                password_entry.encrypted_key,
                password_entry.iv_or_nonce,
                master_key_entry.hashed_key.encode(),
                password_entry.salt,
                password_entry.encryption_algorithm
            ).decode('utf-8')
        except PasswordEntry.DoesNotExist:
            return JsonResponse({
                'success': False,
                'error': 'Contraseña no encontrada'
            }, status=404)
        
        # Verificar contra HaveIBeenPwned
        breach_info = check_password_breach_sync(decrypted_password)
        
        return JsonResponse({
            'success': True,
            'password_id': password_id,
            'breach_info': breach_info
        })
        
    except json.JSONDecodeError:
        return JsonResponse({
            'success': False,
            'error': 'Datos JSON inválidos'
        }, status=400)
    except Exception as e:
        print(f"Error verificando contraseña: {e}")
        return JsonResponse({
            'success': False,
            'error': 'Error interno del servidor'
        }, status=500)

@api_view(['GET'])
@authentication_classes([JWTAuthentication])
@permission_classes([IsAuthenticated])
def api_security_recommendations(request):
    """
    Obtener recomendaciones personalizadas de seguridad
    """
    try:
        password_entries = PasswordEntry.objects.filter(user=request.user)
        total_passwords = password_entries.count()
        
        if total_passwords == 0:
            return JsonResponse({
                'success': True,
                'recommendations': [
                    {
                        'type': 'getting_started',
                        'priority': 'high',
                        'title': 'Comienza a usar el gestor',
                        'description': 'Agrega tus primeras contraseñas para obtener análisis de seguridad personalizado',
                        'action': 'add_password'
                    }
                ]
            })
        
        recommendations = []
        
        # Verificar contraseñas débiles
        # (Esto requeriría desencriptar, pero para recomendaciones generales podemos usar heurísticas)
        
        # Contraseñas antiguas
        old_passwords = password_entries.filter(
            updated_at__lt=timezone.now() - timedelta(days=365)
        ).count()
        
        if old_passwords > 0:
            recommendations.append({
                'type': 'update_old_passwords',
                'priority': 'medium',
                'title': 'Actualizar contraseñas antiguas',
                'description': f'Tienes {old_passwords} contraseñas que no se han actualizado en más de un año',
                'action': 'update_passwords',
                'count': old_passwords
            })
        
        # Algoritmos de encriptación débiles
        weak_algorithms = password_entries.exclude(
            encryption_algorithm__in=['AES', 'ChaCha20']
        ).count()
        
        if weak_algorithms > 0:
            recommendations.append({
                'type': 'upgrade_encryption',
                'priority': 'low',
                'title': 'Actualizar algoritmo de encriptación',
                'description': f'{weak_algorithms} contraseñas usan algoritmos de encriptación menos seguros',
                'action': 'reencrypt_passwords',
                'count': weak_algorithms
            })
        
        # Recomendación general de seguridad
        if total_passwords < 5:
            recommendations.append({
                'type': 'expand_usage',
                'priority': 'low',
                'title': 'Expande el uso del gestor',
                'description': 'Considera migrar más cuentas al gestor de contraseñas para mayor seguridad',
                'action': 'add_more_passwords'
            })
        
        return JsonResponse({
            'success': True,
            'recommendations': recommendations
        })
        
    except Exception as e:
        print(f"Error obteniendo recomendaciones: {e}")
        return JsonResponse({
            'success': False,
            'error': 'Error al obtener recomendaciones'
        }, status=500)
        
# ==========================================
# FUNCIONES DE ANÁLISIS DE SEGURIDAD
# ==========================================

def calculate_password_entropy(password: str) -> float:
    """
    Calcula la entropía de una contraseña en bits
    """
    if not password:
        return 0.0
    
    # Definir los sets de caracteres
    lowercase = set('abcdefghijklmnopqrstuvwxyz')
    uppercase = set('ABCDEFGHIJKLMNOPQRSTUVWXYZ')
    digits = set('0123456789')
    special = set('!@#$%^&*()_+-=[]{}|;:,.<>?')
    
    # Determinar qué sets de caracteres se usan
    charset_size = 0
    password_set = set(password)
    
    if password_set.intersection(lowercase):
        charset_size += 26
    if password_set.intersection(uppercase):
        charset_size += 26
    if password_set.intersection(digits):
        charset_size += 10
    if password_set.intersection(special):
        charset_size += len(special)
    
    # Si hay caracteres que no están en los sets conocidos, agregarlos
    known_chars = lowercase | uppercase | digits | special
    unknown_chars = password_set - known_chars
    charset_size += len(unknown_chars)
    
    # Calcular entropía básica
    if charset_size == 0:
        return 0.0
    
    entropy = len(password) * math.log2(charset_size)
    
    # Reducir entropía por patrones comunes
    # Secuencias (abc, 123)
    sequence_penalty = 0
    for i in range(len(password) - 2):
        substring = password[i:i+3]
        if (substring.lower() in 'abcdefghijklmnopqrstuvwxyz' or 
            substring in '0123456789' or
            substring in '9876543210'):
            sequence_penalty += 2
    
    # Repeticiones
    char_counts = Counter(password)
    repetition_penalty = sum(count - 1 for count in char_counts.values() if count > 1)
    
    # Patrones de teclado (qwerty, asdf)
    keyboard_patterns = ['qwerty', 'asdf', 'zxcv', '1234', '4567']
    keyboard_penalty = 0
    password_lower = password.lower()
    for pattern in keyboard_patterns:
        if pattern in password_lower:
            keyboard_penalty += len(pattern)
    
    # Aplicar penalizaciones
    total_penalty = sequence_penalty + repetition_penalty + keyboard_penalty
    entropy = max(0, entropy - total_penalty)
    
    return entropy

def get_password_strength_category(entropy: float) -> dict:
    """
    Categoriza la fortaleza de la contraseña basada en la entropía
    """
    if entropy >= 70:
        return {
            'level': 'very_strong',
            'label': 'Muy Fuerte',
            'color': '#10b981',
            'score': 100
        }
    elif entropy >= 50:
        return {
            'level': 'strong',
            'label': 'Fuerte',
            'color': '#3b82f6',
            'score': 80
        }
    elif entropy >= 35:
        return {
            'level': 'moderate',
            'label': 'Moderada',
            'color': '#f59e0b',
            'score': 60
        }
    elif entropy >= 25:
        return {
            'level': 'weak',
            'label': 'Débil',
            'color': '#f97316',
            'score': 40
        }
    else:
        return {
            'level': 'very_weak',
            'label': 'Muy Débil',
            'color': '#ef4444',
            'score': 20
        }

def check_password_breach_sync(password: str) -> dict:
    """
    Verifica si una contraseña aparece en HaveIBeenPwned usando k-anonymity
    """
    try:
        # Crear SHA-1 hash de la contraseña
        sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        prefix = sha1_hash[:5]
        suffix = sha1_hash[5:]
        
        # Hacer petición a HaveIBeenPwned API
        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        response = requests.get(url, timeout=5)
        
        if response.status_code == 200:
            # Buscar nuestro hash en la respuesta
            for line in response.text.splitlines():
                hash_suffix, count = line.split(':')
                if hash_suffix == suffix:
                    return {
                        'is_breached': True,
                        'breach_count': int(count),
                        'message': f'Esta contraseña aparece {count} veces en filtraciones de datos conocidas'
                    }
            
            return {
                'is_breached': False,
                'breach_count': 0,
                'message': 'No se encontró en filtraciones conocidas'
            }
        else:
            return {
                'is_breached': False,
                'breach_count': 0,
                'message': 'No se pudo verificar (error del servicio)',
                'error': True
            }
            
    except Exception as e:
        return {
            'is_breached': False,
            'breach_count': 0,
            'message': 'No se pudo verificar (error de conexión)',
            'error': True
        }

def find_duplicate_passwords(passwords: list) -> list:
    """
    Encuentra contraseñas duplicadas
    """
    password_groups = {}
    for pwd_data in passwords:
        pwd = pwd_data['password']
        if pwd in password_groups:
            password_groups[pwd].append(pwd_data)
        else:
            password_groups[pwd] = [pwd_data]
    
    # Retornar solo los grupos con duplicados
    return {k: v for k, v in password_groups.items() if len(v) > 1}

def analyze_password_patterns(passwords: list) -> dict:
    """
    Analiza patrones comunes en las contraseñas
    """
    patterns = {
        'common_prefixes': Counter(),
        'common_suffixes': Counter(),
        'length_distribution': Counter(),
        'character_usage': {
            'uppercase': 0,
            'lowercase': 0,
            'digits': 0,
            'special': 0
        }
    }
    
    for pwd_data in passwords:
        pwd = pwd_data['password']
        
        # Longitud
        patterns['length_distribution'][len(pwd)] += 1
        
        # Prefijos y sufijos comunes (primeros/últimos 3 caracteres)
        if len(pwd) >= 3:
            patterns['common_prefixes'][pwd[:3].lower()] += 1
            patterns['common_suffixes'][pwd[-3:].lower()] += 1
        
        # Uso de caracteres
        if re.search(r'[A-Z]', pwd):
            patterns['character_usage']['uppercase'] += 1
        if re.search(r'[a-z]', pwd):
            patterns['character_usage']['lowercase'] += 1
        if re.search(r'\d', pwd):
            patterns['character_usage']['digits'] += 1
        if re.search(r'[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]', pwd):
            patterns['character_usage']['special'] += 1
    
    return patterns