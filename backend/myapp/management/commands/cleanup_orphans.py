from django.core.management.base import BaseCommand

class Command(BaseCommand):
    help = 'Limpiar archivos huérfanos (registros BD sin archivo en MinIO)'
    
    def add_arguments(self, parser):
        parser.add_argument('--user-id', type=int, help='ID del usuario específico')
        parser.add_argument('--dry-run', action='store_true', help='Solo mostrar qué se eliminaría')
    
    def handle(self, *args, **options):
        from myapp.models import EncryptedFile, User
        from myapp.minio_service import enhanced_minio_service
        
        # Filtrar por usuario si se especifica
        if options['user_id']:
            try:
                user = User.objects.get(id=options['user_id'])
                user_files = EncryptedFile.objects.filter(user=user)
                self.stdout.write(f"Limpiando archivos del usuario: {user.username}")
            except User.DoesNotExist:
                self.stdout.write(self.style.ERROR(f"Usuario {options['user_id']} no encontrado"))
                return
        else:
            user_files = EncryptedFile.objects.all()
            self.stdout.write("Limpiando archivos de todos los usuarios")
        
        orphaned_files = []
        valid_files = 0
        
        self.stdout.write(f"Verificando {user_files.count()} archivos...")
        
        for file_entry in user_files:
            try:
                enhanced_minio_service.client.stat_object(
                    enhanced_minio_service.bucket_name,
                    file_entry.file_path
                )
                valid_files += 1
                
            except Exception as e:
                if "NoSuchKey" in str(e) or "Not found" in str(e):
                    orphaned_files.append(file_entry)
                    self.stdout.write(
                        self.style.WARNING(
                            f"Huérfano: {file_entry.title} (Usuario: {file_entry.user.username})"
                        )
                    )
        
        self.stdout.write(f"\nResultados:")
        self.stdout.write(f"  Archivos válidos: {valid_files}")
        self.stdout.write(f"  Archivos huérfanos: {len(orphaned_files)}")
        
        if options['dry_run']:
            self.stdout.write(self.style.SUCCESS("Ejecución de prueba - no se eliminó nada"))
            return
        
        if orphaned_files:
            # Eliminar huérfanos
            for orphan in orphaned_files:
                orphan.delete()
                self.stdout.write(f"Eliminado: {orphan.title}")
            
            self.stdout.write(
                self.style.SUCCESS(
                    f"Limpieza completada: {len(orphaned_files)} registros eliminados"
                )
            )
        else:
            self.stdout.write(self.style.SUCCESS("No se encontraron archivos huérfanos"))