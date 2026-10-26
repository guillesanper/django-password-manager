"""L1 — mantenimiento programado (N18, AU-17).

Nada purgaba nada: ni los refresh caducados (`outstandingtoken`), ni las sesiones Django, ni
las altas sin confirmar de N17, que sólo se borraban cuando llegaba otra alta. El servicio
`maintenance` ejecuta `infrastructure/maintenance/maintenance.sh` una vez al día; aquí se prueba
el comando nuevo que usa, `purge_pending_registrations`. Los demás son de Django y simplejwt.
"""

from datetime import timedelta

import pytest
from django.core.management import call_command
from django.utils import timezone

from myapp.models import PendingRegistration

pytestmark = [pytest.mark.l1, pytest.mark.django_db]


def _alta(email, caduca):
    return PendingRegistration.objects.create(
        email=email, first_name="A", last_name="B", password_hash="x",
        token_hash=email.ljust(64, "0")[:64], expires_at=caduca,
    )


def test_n18_purga_solo_las_altas_caducadas():
    ahora = timezone.now()
    _alta("vieja@example.test", ahora - timedelta(seconds=1))
    viva = _alta("viva@example.test", ahora + timedelta(hours=1))

    call_command("purge_pending_registrations")

    assert list(PendingRegistration.objects.all()) == [viva]
