"""L1 — batería G de comandos de gestión, migraciones y check de despliegue.

Cubre G8, G9 y G10 (§5):

  - G8  Los comandos `setup_minio_buckets`, `cleanup_sessions` y `cleanup_orphans`
        (nombres reales en myapp/management/commands/) corren sin excepción vía
        call_command. Se ejecutan contra el bucket/Redis de TEST (settings_test los
        reapunta), nunca contra producción.
  - G9  `makemigrations --check --dry-run` no detecta cambios de modelo sin migrar:
        el estado del modelo cuadra con las migraciones 0022-0026, MANUALES a
        propósito (trampa 15). Si alguien toca un modelo sin migrar, esto se pone rojo.
  - G10 `check --deploy` sin W009 (SECRET_KEY débil) ni aviso de DEBUG en cualquier
        pila; en `stack_prod` (TLS activo) además sin W004/W008/W012/W016 (HSTS,
        SSL-redirect, cookies Secure).

No son xfail: con las Fases 0-2 cerradas deben pasar hoy (§3).
"""

from io import StringIO

import pytest
from django.core.checks import run_checks
from django.core.management import call_command

import demo.settings as prod

pytestmark = pytest.mark.l1


# =========================================================================== #
# G8 — los comandos de gestión corren sin lanzar
# =========================================================================== #
@pytest.mark.django_db
def test_g8_setup_minio_buckets_corre_sin_excepcion():
    # Opera sobre el bucket de TEST (settings_test antepone 'test-' a MINIO_BUCKET_NAME);
    # el comando crea el bucket si falta y captura por dentro cualquier fallo de conexión,
    # así que no debe propagar excepción.
    out, err = StringIO(), StringIO()
    call_command("setup_minio_buckets", stdout=out, stderr=err)


@pytest.mark.django_db
def test_g8_cleanup_sessions_corre_sin_excepcion():
    # --dry-run: cuenta sesiones expiradas en la db 15 de test sin borrar nada.
    out, err = StringIO(), StringIO()
    call_command("cleanup_sessions", "--dry-run", stdout=out, stderr=err)


@pytest.mark.django_db
def test_g8_cleanup_orphans_corre_sin_excepcion():
    # --dry-run: con la BD de test vacía no hay EncryptedFile, así que no toca MinIO.
    out, err = StringIO(), StringIO()
    call_command("cleanup_orphans", "--dry-run", stdout=out, stderr=err)


# =========================================================================== #
# G9 — sin cambios de modelo sin migrar (las 0022-0026 son manuales, trampa 15)
# =========================================================================== #
def test_g9_makemigrations_check_sin_cambios_pendientes():
    out, err = StringIO(), StringIO()
    try:
        call_command(
            "makemigrations", "--check", "--dry-run", stdout=out, stderr=err
        )
    except SystemExit as exc:
        # --check hace `sys.exit(1)` cuando el estado del modelo NO está migrado.
        if exc.code:
            pytest.fail(
                "makemigrations --check detectó cambios de modelo sin migrar (el "
                "esquema diverge de las migraciones manuales 0022-0026):\n"
                f"{out.getvalue()}{err.getvalue()}"
            )


# =========================================================================== #
# G10 — check --deploy limpio de los avisos que ya se corrigieron
# =========================================================================== #
def _deploy_ids() -> set:
    """IDs de todos los mensajes de `check --deploy` sobre la config activa."""
    return {m.id for m in run_checks(include_deployment_checks=True)}


def test_g10_check_deploy_sin_w009_ni_debug():
    ids = _deploy_ids()
    assert "security.W009" not in ids, (
        "security.W009: SECRET_KEY débil/por defecto. Debe venir de DJANGO_SECRET_KEY "
        "(os.environ, sin fallback inseguro)."
    )
    # W018 = DEBUG=True en despliegue. settings_test fuerza DEBUG=False, así que aquí
    # actúa de regresión defensiva (nunca debe reaparecer).
    assert "security.W018" not in ids, "security.W018: DEBUG activo en despliegue."


@pytest.mark.stack_prod
def test_g10_check_deploy_prod_sin_avisos_tls():
    # En stack_dev (TLS=false) estos avisos son ESPERADOS: sólo se afirma su ausencia
    # cuando la pila levantó con DJANGO_TLS_ENABLED=true (stack_prod). Se detecta por el
    # `_TLS` ya computado en demo.settings dentro de este contenedor.
    if not prod._TLS:
        pytest.skip(
            "G10 stack_prod: requiere DJANGO_TLS_ENABLED=true (esta pila es stack_dev)."
        )

    ids = _deploy_ids()
    esperados_ausentes = {
        "security.W004": "SECURE_HSTS_SECONDS sin fijar",
        "security.W008": "SECURE_SSL_REDIRECT no activo",
        "security.W012": "SESSION_COOKIE_SECURE no activo",
        "security.W016": "CSRF_COOKIE_SECURE no activo",
    }
    presentes = {wid: motivo for wid, motivo in esperados_ausentes.items() if wid in ids}
    assert not presentes, (
        f"En stack_prod (TLS) no deben aparecer avisos de borde TLS: {presentes}"
    )
