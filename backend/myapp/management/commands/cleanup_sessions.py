# myapp/management/commands/cleanup_sessions.py
from django.core.management.base import BaseCommand
from django.utils import timezone
from django.conf import settings
from django.core.cache import cache
import json
import logging
from ...session_manager import SessionManager

logger = logging.getLogger('session')

class Command(BaseCommand):
    help = 'Limpia sesiones expiradas y realiza mantenimiento del sistema de sesiones'

    def add_arguments(self, parser):
        parser.add_argument(
            '--force',
            action='store_true',
            help='Forzar limpieza incluso si está deshabilitada en configuración',
        )
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Mostrar qué se limpiaría sin hacer cambios',
        )
        parser.add_argument(
            '--verbose',
            action='store_true',
            help='Mostrar información detallada del proceso',
        )

    def handle(self, *args, **options):
        if not getattr(settings, 'SESSION_CLEANUP_ENABLED', True) and not options['force']:
            self.stdout.write(
                self.style.WARNING('Limpieza de sesiones deshabilitada en configuración')
            )
            return

        dry_run = options['dry_run']
        verbose = options['verbose']
        
        if dry_run:
            self.stdout.write(self.style.WARNING('MODO DRY-RUN: No se realizarán cambios'))

        session_manager = SessionManager()
        
        self.stdout.write('Iniciando limpieza de sesiones...')
        
        # Estadísticas iniciales
        initial_stats = self._get_cache_stats()
        if verbose:
            self.stdout.write(f'Estadísticas iniciales: {initial_stats}')

        try:
            if not dry_run:
                # Realizar limpieza real
                session_manager.cleanup_all_expired_sessions()
                self.stdout.write(
                    self.style.SUCCESS('Limpieza de sesiones completada exitosamente')
                )
            else:
                # Simular limpieza
                expired_count = self._count_expired_sessions()
                self.stdout.write(
                    f'Se limpiarían {expired_count} sesiones expiradas'
                )

            # Estadísticas finales
            if verbose:
                final_stats = self._get_cache_stats()
                self.stdout.write(f'Estadísticas finales: {final_stats}')
                
            # Mostrar resumen
            self._show_cleanup_summary(initial_stats, verbose)
            
        except Exception as e:
            logger.error(f'Error durante limpieza de sesiones: {e}')
            self.stdout.write(
                self.style.ERROR(f'Error durante la limpieza: {e}')
            )
            
    def _get_cache_stats(self):
        """Obtiene estadísticas del cache"""
        try:
            # Contar keys relacionados con sesiones
            pattern = f"{SessionManager().session_prefix}*"
            session_count = 0
            
            # Esto requiere Redis
            from django_redis import get_redis_connection
            redis_conn = get_redis_connection("default")
            
            for key in redis_conn.scan_iter(match=pattern):
                session_count += 1
                
            return {
                'total_session_keys': session_count,
                'timestamp': timezone.now().isoformat()
            }
        except Exception as e:
            logger.warning(f'No se pudieron obtener estadísticas del cache: {e}')
            return {'error': str(e)}
    
    def _count_expired_sessions(self):
        """Cuenta sesiones expiradas sin eliminarlas"""
        try:
            session_manager = SessionManager()
            pattern = f"{session_manager.session_prefix}*"
            expired_count = 0
            
            from django_redis import get_redis_connection
            redis_conn = get_redis_connection("default")
            
            for key in redis_conn.scan_iter(match=pattern):
                session_data = cache.get(key.decode())
                if session_data:
                    try:
                        session = json.loads(session_data)
                        if not session_manager.is_session_valid(session):
                            expired_count += 1
                    except (json.JSONDecodeError, KeyError):
                        expired_count += 1  # Sesión corrupta también se cuenta como expirada
                        
            return expired_count
        except Exception as e:
            logger.error(f'Error contando sesiones expiradas: {e}')
            return 0
    
    def _show_cleanup_summary(self, initial_stats, verbose):
        """Muestra resumen de la limpieza"""
        self.stdout.write('\n' + '='*50)
        self.stdout.write('RESUMEN DE LIMPIEZA DE SESIONES')
        self.stdout.write('='*50)
        
        if 'error' not in initial_stats:
            self.stdout.write(f'Sesiones iniciales: {initial_stats["total_session_keys"]}')
        
        self.stdout.write(f'Proceso completado: {timezone.now().strftime("%Y-%m-%d %H:%M:%S")}')
        
        if verbose:
            # Información adicional sobre configuración
            self.stdout.write('\nConfiguración actual:')
            self.stdout.write(f'  - Session timeout: {getattr(settings, "SESSION_TIMEOUT", "No configurado")}s')
            self.stdout.write(f'  - Max sessions per user: {getattr(settings, "MAX_SESSIONS_PER_USER", "No configurado")}')
            self.stdout.write(f'  - Cleanup enabled: {getattr(settings, "SESSION_CLEANUP_ENABLED", True)}')
        
        self.stdout.write('\n' + '='*50)