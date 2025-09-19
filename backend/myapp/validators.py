# myapp/validators.py - Validadores personalizados mejorados

import re
from django.core.exceptions import ValidationError
from django.utils.translation import gettext as _

class CustomPasswordValidator:
    """
    Validador personalizado de contraseñas con reglas estrictas para gestores de contraseñas
    """
    
    def __init__(self, min_length=12, require_symbols=True, require_mixed_case=True, 
                 require_numbers=True, max_consecutive=2, forbidden_patterns=None):
        self.min_length = min_length
        self.require_symbols = require_symbols
        self.require_mixed_case = require_mixed_case
        self.require_numbers = require_numbers
        self.max_consecutive = max_consecutive
        self.forbidden_patterns = forbidden_patterns or [
            'password', '123456', 'qwerty', 'admin', 'user', 'login',
            'master', 'secret', 'pass', '1234', 'abcd'
        ]
    
    def validate(self, password, user=None):
        """
        Valida la contraseña según reglas estrictas de seguridad
        """
        errors = []
        
        # Verificar longitud mínima
        if len(password) < self.min_length:
            errors.append(
                ValidationError(
                    f"La contraseña debe tener al menos {self.min_length} caracteres.",
                    code='password_too_short',
                )
            )
        
        # Verificar longitud máxima (prevenir DoS)
        if len(password) > 128:
            errors.append(
                ValidationError(
                    "La contraseña no puede exceder 128 caracteres.",
                    code='password_too_long',
                )
            )
        
        # Verificar mayúsculas y minúsculas
        if self.require_mixed_case:
            if not re.search(r'[A-Z]', password):
                errors.append(
                    ValidationError(
                        "La contraseña debe contener al menos una letra mayúscula.",
                        code='password_no_upper',
                    )
                )
            if not re.search(r'[a-z]', password):
                errors.append(
                    ValidationError(
                        "La contraseña debe contener al menos una letra minúscula.",
                        code='password_no_lower',
                    )
                )
        
        # Verificar números
        if self.require_numbers:
            if not re.search(r'\d', password):
                errors.append(
                    ValidationError(
                        "La contraseña debe contener al menos un número.",
                        code='password_no_number',
                    )
                )
        
        # Verificar símbolos especiales
        if self.require_symbols:
            if not re.search(r'[!@#$%^&*()_+\-=\[\]{}|;:,.<>?/\\~`"]', password):
                errors.append(
                    ValidationError(
                        "La contraseña debe contener al menos un símbolo especial (!@#$%^&* etc.).",
                        code='password_no_symbol',
                    )
                )
        
        # Verificar caracteres consecutivos repetidos
        if self.max_consecutive:
            for i in range(len(password) - self.max_consecutive):
                if len(set(password[i:i+self.max_consecutive+1])) == 1:
                    errors.append(
                        ValidationError(
                            f"La contraseña no puede tener más de {self.max_consecutive} caracteres iguales consecutivos.",
                            code='password_too_many_consecutive',
                        )
                    )
                    break
        
        # Verificar secuencias comunes
        sequences = ['123456', 'abcdef', 'qwerty', '654321', 'fedcba']
        password_lower = password.lower()
        for seq in sequences:
            if seq in password_lower or seq[::-1] in password_lower:
                errors.append(
                    ValidationError(
                        "La contraseña no puede contener secuencias comunes de caracteres.",
                        code='password_common_sequence',
                    )
                )
                break
        
        # Verificar patrones prohibidos
        for pattern in self.forbidden_patterns:
            if pattern.lower() in password_lower:
                errors.append(
                    ValidationError(
                        f"La contraseña no puede contener palabras comunes como '{pattern}'.",
                        code='password_common_word',
                    )
                )
        
        # Verificar que no contenga información del usuario
        if user:
            user_info = [
                user.username.lower() if hasattr(user, 'username') else '',
                user.email.lower().split('@')[0] if hasattr(user, 'email') else '',
                user.first_name.lower() if hasattr(user, 'first_name') else '',
                user.last_name.lower() if hasattr(user, 'last_name') else '',
            ]
            
            for info in user_info:
                if info and len(info) >= 3 and info in password_lower:
                    errors.append(
                        ValidationError(
                            "La contraseña no puede contener información personal.",
                            code='password_personal_info',
                        )
                    )
        
        # VALIDACIÓN DE FECHAS MEJORADA - Más específica y menos restrictiva
        if self.contains_obvious_dates(password):
            errors.append(
                ValidationError(
                    "La contraseña no puede contener fechas obvias.",
                    code='password_contains_date',
                )
            )
        
        if errors:
            raise ValidationError(errors)
    
    def contains_obvious_dates(self, password):
        """
        Detecta fechas obvias pero permite números aleatorios
        """
        import datetime
        current_year = datetime.datetime.now().year
        
        # Patrones de fechas más específicos
        date_patterns = [
            # Fechas con separadores
            r'\d{1,2}[/\-\.]\d{1,2}[/\-\.]\d{4}',  # DD/MM/YYYY, MM/DD/YYYY
            r'\d{4}[/\-\.]\d{1,2}[/\-\.]\d{1,2}',  # YYYY/MM/DD
            
            # Fechas sin separadores (8 dígitos seguidos que parezcan fechas)
            r'(19|20)\d{6}',  # Fechas que empiecen con 19 o 20 (ej: 20230115)
            r'\d{2}(0[1-9]|1[0-2])(19|20)\d{2}',  # DDMMYYYY
        ]
        
        # Verificar patrones de fechas
        for pattern in date_patterns:
            if re.search(pattern, password):
                return True
        
        # Verificar años realistas (1900-2050) que estén aislados o en contexto de fecha
        year_pattern = r'(?:^|[^0-9])(19[0-9]{2}|20[0-4][0-9]|2050)(?:[^0-9]|$)'
        if re.search(year_pattern, password):
            return True
        
        # Verificar secuencias de 8 dígitos que podrían ser fechas YYYYMMDD o DDMMYYYY
        eight_digit_pattern = r'\d{8}'
        matches = re.findall(eight_digit_pattern, password)
        for match in matches:
            if self.looks_like_date(match):
                return True
        
        return False
    
    def looks_like_date(self, eight_digits):
        """
        Determina si una secuencia de 8 dígitos parece una fecha
        """
        # Verificar formato YYYYMMDD
        if eight_digits[:4].isdigit():
            year = int(eight_digits[:4])
            if 1900 <= year <= 2050:
                month = int(eight_digits[4:6])
                day = int(eight_digits[6:8])
                if 1 <= month <= 12 and 1 <= day <= 31:
                    return True
        
        # Verificar formato DDMMYYYY
        if eight_digits[4:].isdigit():
            year = int(eight_digits[4:])
            if 1900 <= year <= 2050:
                day = int(eight_digits[:2])
                month = int(eight_digits[2:4])
                if 1 <= month <= 12 and 1 <= day <= 31:
                    return True
        
        return False
    
    def get_help_text(self):
        """Texto de ayuda para el validador"""
        return (
            f"La contraseña debe tener al menos {self.min_length} caracteres, "
            "incluir mayúsculas, minúsculas, números y símbolos especiales. "
            "No puede contener secuencias comunes, palabras obvias, fechas obvias o información personal."
        )