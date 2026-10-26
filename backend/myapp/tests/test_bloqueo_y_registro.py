"""L1 — el bloqueo del login no se puede provocar y el registro no enumera cuentas (N17).

Cada petición atraviesa la cadena REAL con `Client`, como en `test_rate_limit.py`. La IP
del cliente llega en X-Forwarded-For desde la IP de nginx, y el reloj (`time.time`, que
leen tanto la vista como el limitador) es falso para poder esperar sin dormir.

  - AU-07  10 fallos por email en 30 min bloqueaban la cuenta 30 min ANTES de comprobar la
           contraseña: con 10 peticiones desde 2 IPs cualquiera dejaba sin login a quien
           quisiera, renovable. Ahora el bloqueo duro es por (email, IP) y por email sólo hay
           un retardo creciente (1 s, 2 s, 4 s… hasta 60 s) entre intentos: la víctima,
           desde otra IP y con su contraseña, entra en cuanto pasa el retardo.
  - AU-08  El registro respondía "Ya existe una cuenta con este email": un oráculo de
           existencia. Ahora es en dos pasos: el alta responde siempre lo mismo y manda un
           correo (el enlace de activación, o un aviso si la cuenta ya existe); la cuenta
           se crea al confirmar con el enlace Y la contraseña. Confirmar exige la contraseña
           para que quien da de alta un email ajeno no consiga que el dueño, al pulsar el
           enlace, active una cuenta con la contraseña del atacante.
  - AU-30  El "máximo 3 registros por hora" de la vista sólo contaba los fallidos, y
           `validate_password` sin usuario anulaba `UserAttributeSimilarityValidator`.

La parte de cliente (el SPA muestra "revisa tu correo" y confirma desde el enlace) la cubre
`frontend/src/services/authService.test.ts` (L3).
"""

import json
import re
from datetime import timedelta
from unittest import mock

import pytest
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core import mail
from django.test import Client
from django.utils import timezone

from myapp.middleware import RateLimitMiddleware
from myapp.utils import request_utils

pytestmark = [pytest.mark.l1, pytest.mark.django_db]

User = get_user_model()

NGINX_IP = "172.28.0.10"
VICTIMA_EMAIL = "victima.n17@example.test"
VICTIMA_PASSWORD = "Wren$Kilo7pluto-N17"
NUEVO = {
    "first_name": "Ramona",
    "last_name": "Quintero",
    "email": "ramona.n17@example.test",
    "password": "Tundra#Faro92-lince",
}


class Reloj:
    """Sustituye a `time.time` en la vista y en el limitador."""

    def __init__(self):
        self.ahora = 1_900_000_000.0

    def __call__(self):
        return self.ahora

    def avanza(self, segundos):
        self.ahora += segundos


@pytest.fixture(autouse=True)
def _nginx_de_confianza(settings):
    settings.TRUSTED_PROXIES = [f"{NGINX_IP}/32"]
    settings.TRUSTED_PROXY_HOPS = 1
    request_utils._trusted_networks = None
    yield
    request_utils._trusted_networks = None


@pytest.fixture
def reloj():
    r = Reloj()
    with mock.patch("time.time", r):
        yield r


@pytest.fixture
def victima(django_user_model):
    return django_user_model.objects.create_user(
        username="victima_n17", email=VICTIMA_EMAIL, password=VICTIMA_PASSWORD,
    )


def _post(path, body, ip):
    return Client(raise_request_exception=False).post(
        path, data=json.dumps(body), content_type="application/json",
        REMOTE_ADDR=NGINX_IP, HTTP_X_FORWARDED_FOR=ip,
    )


def _login(email, password, ip):
    return _post("/auth/login/", {"email": email, "password": password}, ip)


def _registro(datos, ip="198.51.100.80"):
    return _post("/auth/register/", datos, ip)


def _confirmar(token, password, ip="198.51.100.80"):
    return _post("/auth/register/confirm/", {"token": token, "password": password}, ip)


def _token_del_correo(mensaje):
    m = re.search(r"/verificar-email#token=([A-Za-z0-9_\-]+)", mensaje.body)
    assert m, f"el correo no lleva enlace de activación:\n{mensaje.body}"
    return m.group(1)


def _diez_fallos_desde_dos_ips(email):
    """Lo que hacía el atacante del informe: 5 fallos por IP (el límite por IP) desde 2 IPs."""
    for ip in ("203.0.113.1", "203.0.113.2"):
        for _ in range(5):
            r = _login(email, "Contraseña-equivocada-1!", ip)
            assert r.status_code == 400, r.content


# =========================================================================== #
# AU-07 — el bloqueo por email ya no deja fuera a la víctima
# =========================================================================== #
def test_n17_la_victima_entra_desde_otra_ip_tras_el_retardo(victima, reloj):
    _diez_fallos_desde_dos_ips(VICTIMA_EMAIL)

    r = _login(VICTIMA_EMAIL, VICTIMA_PASSWORD, "198.51.100.9")
    if r.status_code == 429:
        espera = int(r["Retry-After"])
        assert 1 <= espera <= 60, f"retardo fuera de rango: {espera}"
        reloj.avanza(espera)
        r = _login(VICTIMA_EMAIL, VICTIMA_PASSWORD, "198.51.100.9")

    assert r.status_code == 200, (
        f"la víctima, desde una IP limpia y con su contraseña, no entra: {r.status_code} "
        f"{r.content[:200]!r}. 10 fallos ajenos no deben bloquear la cuenta."
    )


def test_n17_el_retardo_por_email_frena_sin_comprobar_la_contrasena(victima, reloj):
    _diez_fallos_desde_dos_ips(VICTIMA_EMAIL)

    with mock.patch("myapp.views.auth_views.authenticate") as autenticar:
        r = _login(VICTIMA_EMAIL, "Otra-equivocada-2!", "203.0.113.3")
    assert r.status_code == 429, r.content
    assert int(r["Retry-After"]) == 1
    autenticar.assert_not_called()  # durante el retardo no se prueba ninguna contraseña

    # Pasado el retardo se comprueba, y cada fallo más duplica la espera.
    reloj.avanza(1)
    assert _login(VICTIMA_EMAIL, "Otra-equivocada-2!", "203.0.113.3").status_code == 400
    r = _login(VICTIMA_EMAIL, "Otra-equivocada-3!", "203.0.113.4")
    assert r.status_code == 429
    assert int(r["Retry-After"]) == 2


def test_n17_el_retardo_no_pasa_de_un_minuto(victima, reloj):
    _diez_fallos_desde_dos_ips(VICTIMA_EMAIL)
    for i in range(10):
        reloj.avanza(60)
        r = _login(VICTIMA_EMAIL, "Otra-equivocada-2!", f"203.0.113.{10 + i}")
        assert r.status_code == 400, r.content
    r = _login(VICTIMA_EMAIL, VICTIMA_PASSWORD, "198.51.100.9")
    assert r.status_code == 429
    assert int(r["Retry-After"]) == 60


def test_n17_el_bloqueo_duro_es_por_email_e_ip(victima, reloj, django_user_model, monkeypatch):
    """Una IP que acumula 10 fallos contra un email queda fuera de ESE email 30 min, aunque
    reinicie su contador por IP entrando en su propia cuenta. Las demás IPs, no."""
    monkeypatch.setitem(RateLimitMiddleware.LIMITS, "auth", (1000, 300, "límite de test"))
    django_user_model.objects.create_user(
        username="atacante_n17", email="atacante.n17@example.test", password=VICTIMA_PASSWORD,
    )
    ip = "203.0.113.50"
    for _ in range(5):
        for _ in range(2):
            reloj.avanza(61)
            assert _login(VICTIMA_EMAIL, "Contraseña-equivocada-1!", ip).status_code == 400
        # Entrar en su cuenta le reinicia el límite de 5 fallos por IP.
        assert _login("atacante.n17@example.test", VICTIMA_PASSWORD, ip).status_code == 200

    reloj.avanza(61)
    r = _login(VICTIMA_EMAIL, VICTIMA_PASSWORD, ip)
    assert r.status_code == 403, f"la IP que acumuló 10 fallos sigue probando: {r.status_code}"
    assert _login(VICTIMA_EMAIL, VICTIMA_PASSWORD, "198.51.100.9").status_code == 200

    reloj.avanza(1800)
    assert _login(VICTIMA_EMAIL, VICTIMA_PASSWORD, ip).status_code == 200


def test_n17_el_retardo_no_distingue_si_la_cuenta_existe(reloj):
    _diez_fallos_desde_dos_ips("nadie.n17@example.test")
    r = _login("nadie.n17@example.test", "Contraseña-equivocada-1!", "203.0.113.3")
    assert r.status_code == 429
    assert int(r["Retry-After"]) == 1


# =========================================================================== #
# AU-08 — registro en dos pasos: la respuesta no dice si el email existe
# =========================================================================== #
def test_n17_el_registro_responde_igual_exista_o_no_el_email(victima):
    nuevo = _registro(NUEVO, ip="198.51.100.81")
    existente = _registro({**NUEVO, "email": VICTIMA_EMAIL}, ip="198.51.100.82")

    assert nuevo.status_code == existente.status_code == 202, (nuevo.content, existente.content)
    assert nuevo.json() == existente.json()
    for r in (nuevo, existente):
        assert settings.JWT_AUTH_COOKIE not in r.cookies, "el alta no abre sesión"
    # Cada dirección recibe un correo: el enlace, o el aviso de que ya tiene cuenta.
    assert sorted(m.to[0] for m in mail.outbox) == sorted([NUEVO["email"], VICTIMA_EMAIL])
    aviso = next(m for m in mail.outbox if m.to == [VICTIMA_EMAIL])
    assert "verificar-email" not in aviso.body
    assert not User.objects.filter(email=NUEVO["email"]).exists()


def test_n17_la_cuenta_se_crea_al_confirmar_con_enlace_y_contrasena():
    assert _registro(NUEVO).status_code == 202
    assert len(mail.outbox) == 1
    enlace = re.search(r"\S*/verificar-email#token=\S+", mail.outbox[0].body).group(0)
    assert enlace.startswith(settings.PUBLIC_URL + "/"), (
        f"el enlace debe salir de PUBLIC_URL, no de la cabecera Host: {enlace}"
    )
    token = _token_del_correo(mail.outbox[0])

    r = _confirmar(token, NUEVO["password"])
    assert r.status_code == 200, r.content
    user = User.objects.get(email=NUEVO["email"])
    assert user.is_active and user.check_password(NUEVO["password"])
    assert (user.first_name, user.last_name) == (NUEVO["first_name"], NUEVO["last_name"])
    assert r.json()["user"]["hasMasterKey"] is False
    assert r.cookies[settings.JWT_AUTH_COOKIE].value, "confirmar abre sesión como antes el alta"

    # El enlace es de un solo uso.
    assert _confirmar(token, NUEVO["password"]).status_code == 400


def test_n17_confirmar_exige_la_contrasena_del_alta():
    """Quien da de alta el email de otro elige la contraseña. Si bastase el enlace, el dueño,
    al pulsarlo, activaría una cuenta cuya contraseña conoce el atacante."""
    _registro(NUEVO)
    token = _token_del_correo(mail.outbox[0])

    for _ in range(4):
        assert _confirmar(token, "Otra#Contrasena-99").status_code == 400
    assert not User.objects.filter(email=NUEVO["email"]).exists()

    # Al quinto fallo el alta pendiente se descarta: ni la buena la activa ya.
    assert _confirmar(token, "Otra#Contrasena-99").status_code == 400
    assert _confirmar(token, NUEVO["password"]).status_code == 400
    assert not User.objects.filter(email=NUEVO["email"]).exists()


def test_n17_el_enlace_caduca():
    from myapp.models import PendingRegistration

    _registro(NUEVO)
    token = _token_del_correo(mail.outbox[0])
    PendingRegistration.objects.update(expires_at=timezone.now() - timedelta(seconds=1))
    assert _confirmar(token, NUEVO["password"]).status_code == 400
    assert not User.objects.filter(email=NUEVO["email"]).exists()


def test_n17_dos_altas_del_mismo_email_solo_una_cuenta():
    _registro(NUEVO, ip="198.51.100.81")
    _registro({**NUEVO, "password": "Otra#Contrasena-99"}, ip="198.51.100.82")
    primero, segundo = (_token_del_correo(m) for m in mail.outbox)

    assert _confirmar(segundo, "Otra#Contrasena-99").status_code == 200
    assert _confirmar(primero, NUEVO["password"]).status_code == 400
    assert User.objects.filter(email=NUEVO["email"]).count() == 1


def test_n17_sin_correo_falla_igual_exista_o_no(victima):
    from myapp.models import PendingRegistration

    with mock.patch("django.core.mail.EmailMessage.send", side_effect=OSError("SMTP caído")):
        nuevo = _registro(NUEVO, ip="198.51.100.81")
        existente = _registro({**NUEVO, "email": VICTIMA_EMAIL}, ip="198.51.100.82")
    assert nuevo.status_code == existente.status_code == 503
    assert nuevo.json() == existente.json()
    assert not PendingRegistration.objects.exists(), "un alta sin correo no debe quedar pendiente"


def test_n17_tope_de_correos_por_direccion():
    """Nadie puede usar el alta para inundar un buzón ajeno: 5 correos por dirección y hora.
    Pasado el tope la respuesta es la misma, sólo que no sale correo."""
    for i in range(7):
        assert _registro(NUEVO, ip=f"198.51.100.{90 + i}").status_code == 202
    assert len(mail.outbox) == 5


# =========================================================================== #
# AU-30 — el límite de la vista cuenta las altas y los validadores ven al usuario
# =========================================================================== #
def test_n17_el_limite_de_registros_cuenta_tambien_los_que_salen_bien():
    for i in range(3):
        r = _registro({**NUEVO, "email": f"alta{i}.n17@example.test"}, ip="198.51.100.77")
        assert r.status_code == 202, r.content
    r = _registro({**NUEVO, "email": "alta3.n17@example.test"}, ip="198.51.100.77")
    assert r.status_code == 429, f"la cuarta alta de la hora desde la misma IP pasó: {r.status_code}"


def test_n17_la_contrasena_no_puede_parecerse_al_email_ni_al_nombre():
    datos = {
        "first_name": "Bartolome",
        "last_name": "Quintero",
        "email": "bartolome.quintero@example.test",
        "password": "Bartolome.Quintero1!",
    }
    r = _registro(datos)
    assert r.status_code == 400, f"aceptó una contraseña que es el email: {r.status_code}"
    error = r.json()["error"].lower()
    assert "similar" in error or "personal" in error, error
    assert not mail.outbox
