# myapp/authentication.py - Backend personalizado para autenticación por email
from django.contrib.auth.backends import ModelBackend
from django.contrib.auth.models import User
from django.db.models import Q

class EmailBackend(ModelBackend):
    """
    Backend de autenticación personalizado que permite login con email o username
    """
    
    def authenticate(self, request, username=None, password=None, email=None, **kwargs):
        try:
            # Si se proporciona email directamente, usarlo
            if email:
                user = User.objects.get(email=email)
            # Si no, intentar con username que puede ser email o username
            elif username:
                # Intentar encontrar por email primero, luego por username
                user = User.objects.get(Q(email=username) | Q(username=username))
            else:
                return None
            
            # Verificar la contraseña
            if user.check_password(password):
                return user
            else:
                return None
                
        except User.DoesNotExist:
            return None
        except User.MultipleObjectsReturned:
            # Si hay múltiples usuarios, intentar con el email exacto
            try:
                if email:
                    user = User.objects.get(email=email)
                elif username and '@' in username:
                    user = User.objects.get(email=username)
                else:
                    user = User.objects.get(username=username)
                    
                if user.check_password(password):
                    return user
            except User.DoesNotExist:
                pass
            
            return None
    
    def get_user(self, user_id):
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None