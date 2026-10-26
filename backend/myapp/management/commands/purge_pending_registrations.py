"""Borra las altas pendientes caducadas (N18). Lo ejecuta el servicio `maintenance` a diario.

Antes de N18 sólo se purgaban cuando llegaba un alta nueva (`request_registration`): sin altas,
las caducadas se quedaban en la base, con su email y el hash de su contraseña.
"""

from django.core.management.base import BaseCommand
from django.utils import timezone

from myapp.models import PendingRegistration


class Command(BaseCommand):
    help = 'Borra las altas pendientes de confirmar cuyo enlace ya caducó'

    def handle(self, *args, **options):
        deleted, _ = PendingRegistration.objects.filter(expires_at__lte=timezone.now()).delete()
        self.stdout.write(f"purge_pending_registrations: {deleted} altas caducadas borradas")
