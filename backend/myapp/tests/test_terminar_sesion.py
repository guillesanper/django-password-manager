"""L1 — terminar una sesión desde la pantalla de sesiones la cierra de verdad (N14).

Cada navegador es un `Client` que hace login por `/auth/login/`, así que pasa por la cadena
real: el login emite el refresh con su `sid` (N9) y `SessionCreationMiddleware` crea la
sesión de seguimiento atada a ese `sid`.

  - N14   «Terminar sesión» sólo borraba la entrada de Redis: el dispositivo seguía
          renovando su refresh 7 días, su access valía hasta 60 min y además la vista
          respondía 500 (`ActivityLog` no tiene `additional_data`). Ahora el `sid` del login
          pasa a `RevokedSession`: su access deja de autenticar (cookie o cabecera) y su
          refresh de renovarse, también el que ya había rotado. «Cerrar todas las demás»
          revoca además los logins que no salen en la lista, y marcar una sesión como
          sospechosa, que la saca de la lista, también la cierra.
          `api_refresh_session_security` daba DataError con un `event_type` de 34 caracteres
          sobre un `max_length=30` (parte de AU-13).
"""

import json
from datetime import timedelta

import pytest
from django.test import Client
from django.utils import timezone
from rest_framework_simplejwt.tokens import RefreshToken

from myapp.models import ActivityLog, RevokedSession, SecurityEvent
from myapp.session_manager import SessionManager
from myapp.utils.cache_utils import lenient_set
from myapp.utils.login_session import revoke_sessions, stamp_session_id

pytestmark = pytest.mark.l1

FIREFOX = "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0"
CHROME = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
)


def _login(zk_user, user_agent=FIREFOX):
    """Navegador con la sesión de un login real."""
    client = Client(raise_request_exception=False, HTTP_USER_AGENT=user_agent)
    r = client.post("/auth/login/", data={
        "email": zk_user.credentials["email"],
        "password": zk_user.credentials["password"],
    }, content_type="application/json")
    assert r.status_code == 200, r.content
    return client


def _sesion_de(user, user_agent):
    """La sesión de seguimiento del navegador `user_agent`, leída directamente de Redis. Cada
    test usa un navegador distinto por login, que es lo que ve el usuario en la lista."""
    for session in SessionManager().get_user_sessions(user.id):
        if session["device_info"]["user_agent"] == user_agent:
            return session
    raise AssertionError(f"no hay sesión de seguimiento para {user_agent}")


def _post(client, path, data):
    return client.post(path, data=data, content_type="application/json")


def _dentro(client):
    """True si el access del navegador sigue autenticando."""
    return client.get("/auth/check/").status_code == 200


def _renueva(client):
    """True si el refresh del navegador sigue renovándose."""
    return client.post("/api/token/refresh/").status_code == 200


def _terminar(client, session_id):
    return _post(client, "/api/sessions/terminate/", {"session_id": session_id})


# --------------------------------------------------------------------------- #
# N14 — terminar una sesión revoca su access y su refresh
# --------------------------------------------------------------------------- #
@pytest.mark.django_db
def test_n14_terminar_revoca_access_y_refresh(zk_user):
    portatil = _login(zk_user)
    movil = _login(zk_user, user_agent=CHROME)
    assert _dentro(portatil)

    r = _terminar(movil, _sesion_de(zk_user.user, FIREFOX)["session_id"])

    assert r.status_code == 200, r.content
    assert not _dentro(portatil), "el access del portátil sigue autenticando"
    assert not _renueva(portatil), "el refresh del portátil sigue renovándose"
    assert _dentro(movil) and _renueva(movil), "terminar otra sesión echó también a quien la terminó"
    assert ActivityLog.objects.filter(
        user=zk_user.user, activity_type="session_terminated"
    ).count() == 1


@pytest.mark.django_db
def test_n14_terminar_alcanza_al_refresh_ya_rotado(zk_user):
    """La blacklist del `jti` no bastaría: el refresh vivo ya no es el del login."""
    portatil = _login(zk_user)
    assert _renueva(portatil)
    movil = _login(zk_user, user_agent=CHROME)

    assert _terminar(movil, _sesion_de(zk_user.user, FIREFOX)["session_id"]).status_code == 200
    assert not _renueva(portatil)


@pytest.mark.django_db
def test_n14_terminar_revoca_tambien_por_la_cabecera_bearer(zk_user):
    portatil = _login(zk_user)
    access = portatil.cookies["access_token"].value
    movil = _login(zk_user, user_agent=CHROME)

    assert _terminar(movil, _sesion_de(zk_user.user, FIREFOX)["session_id"]).status_code == 200
    r = Client().get("/auth/check/", HTTP_AUTHORIZATION=f"Bearer {access}")
    assert r.status_code == 401


@pytest.mark.django_db
def test_n14_no_se_puede_terminar_la_sesion_actual_aunque_falte_la_cookie(zk_user):
    """La cookie `session_id` puede no llegar; el `sid` del JWT identifica la sesión igual."""
    movil = _login(zk_user)
    session_id = _sesion_de(zk_user.user, FIREFOX)["session_id"]
    del movil.cookies["session_id"]

    r = _terminar(movil, session_id)

    assert r.status_code == 400
    assert not RevokedSession.objects.exists()
    assert _dentro(movil)


@pytest.mark.django_db
def test_n14_sesion_sin_sid_no_se_da_por_terminada(zk_user):
    """Una sesión de seguimiento anterior a N14 no sabe qué tokens son suyos: se dice y se
    deja en la lista, en vez de quitarla sin cerrar nada."""
    movil = _login(zk_user)
    antigua = _login(zk_user, user_agent=CHROME)
    session = _sesion_de(zk_user.user, CHROME)
    manager = SessionManager()
    session["login_sid"] = None
    lenient_set(f"{manager.session_prefix}{session['session_id']}", json.dumps(session), 3600)

    r = _terminar(movil, session["session_id"])

    assert r.status_code == 409, r.content
    assert manager.get_session(session["session_id"]) is not None
    assert _dentro(antigua)


@pytest.mark.django_db
def test_n14_la_lista_no_expone_el_sid(zk_user):
    movil = _login(zk_user)
    r = movil.get("/api/sessions/list/")
    assert r.status_code == 200, r.content
    sesiones = r.json()["sessions"]["sessions"]
    assert sesiones
    assert all("login_sid" not in s for s in sesiones)


# --------------------------------------------------------------------------- #
# N14 — cerrar todas las demás alcanza también a las que no salen en la lista
# --------------------------------------------------------------------------- #
@pytest.mark.django_db
def test_n14_terminar_todas_revoca_las_demas_y_las_que_no_salen_en_la_lista(zk_user):
    portatil = _login(zk_user)
    movil = _login(zk_user, user_agent=CHROME)
    # Un login sin sesión de seguimiento (su entrada en Redis caducó, o es un registro).
    oculto = stamp_session_id(RefreshToken.for_user(zk_user.user))
    access_oculto = str(oculto.access_token)

    r = _post(movil, "/api/sessions/terminate-all/", {"confirm": True})

    assert r.status_code == 200, r.content
    assert r.json()["terminated_count"] == 2
    assert not _dentro(portatil) and not _renueva(portatil)
    assert Client().get("/auth/check/", HTTP_AUTHORIZATION=f"Bearer {access_oculto}").status_code == 401
    r = Client().post("/api/token/refresh/", data={"refresh": str(oculto)}, content_type="application/json")
    assert r.status_code == 401
    assert _dentro(movil) and _renueva(movil)


# --------------------------------------------------------------------------- #
# N14 — marcar como sospechosa saca la sesión de la lista, así que también la cierra
# --------------------------------------------------------------------------- #
@pytest.mark.django_db
def test_n14_marcar_como_sospechosa_revoca(zk_user):
    portatil = _login(zk_user)
    movil = _login(zk_user, user_agent=CHROME)

    r = _post(movil, "/api/sessions/flag-suspicious/", {
        "session_id": _sesion_de(zk_user.user, FIREFOX)["session_id"],
    })

    assert r.status_code == 200, r.content
    assert r.json()["revoked"] is True
    assert not _dentro(portatil) and not _renueva(portatil)
    assert _dentro(movil)


# --------------------------------------------------------------------------- #
# Parte de AU-13 — el `event_type` cabe en la columna
# --------------------------------------------------------------------------- #
@pytest.mark.django_db
def test_n14_validacion_fallida_registra_el_evento(zk_user):
    movil = _login(zk_user, user_agent=FIREFOX)
    r = movil.post("/api/sessions/refresh-security/", HTTP_USER_AGENT=CHROME)
    assert r.status_code == 403, r.content
    assert SecurityEvent.objects.filter(user=zk_user.user, event_type="session_validation_failed").exists()


@pytest.mark.django_db
def test_n14_revocar_purga_las_filas_que_ya_no_casan(zk_user):
    RevokedSession.objects.create(sid="caducada", user=zk_user.user, expires_at=timezone.now() - timedelta(seconds=1))
    revoke_sessions(zk_user.user, ["nueva"])
    assert list(RevokedSession.objects.values_list("sid", flat=True)) == ["nueva"]
