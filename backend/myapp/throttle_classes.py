from rest_framework.decorators import api_view, throttle_classes
from rest_framework.throttling import UserRateThrottle, AnonRateThrottle
from django_ratelimit.decorators import ratelimit

# Throttling personalizado para diferentes tipos de operaciones
class AuthThrottle(AnonRateThrottle):
    scope = 'login'  # 10/minute según settings

class SensitiveOperationThrottle(UserRateThrottle):
    scope = 'user'   # 10000/hour - muy permisivo

class DataFetchThrottle(UserRateThrottle):
    scope = 'api_data'  # 2000/hour - muy permisivo
