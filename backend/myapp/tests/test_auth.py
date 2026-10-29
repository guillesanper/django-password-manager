"""L1 — autenticación: blacklist de refresh y señuelo de temporización.

Cubre A5 (parte L1) y A6-a (§4.3):

  - A5   Tras el logout, el refresh de ESTE dispositivo queda en BlacklistedToken y
         reutilizarlo ya no vale; y un usuario no puede invalidar el refresh de otro
         (comprobación de propiedad en SecureLogoutView._revoke_refresh_tokens).
  - A6-a EmailBackend ejecuta el hasher Argon2 también con un usuario inexistente
         (señuelo), de modo que el coste no delata si la cuenta existe.

Ninguno es xfail: con las Fases 0-2 cerradas deben pasar hoy (§3).
"""

import pytest
from django.conf import settings
from django.test import RequestFactory
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.token_blacklist.models import BlacklistedToken
from rest_framework_simplejwt.tokens import RefreshToken

from myapp.views import SecureLogoutView

pytestmark = pytest.mark.l1


# --------------------------------------------------------------------------- #
# A5 — el logout invalida el refresh del dispositivo (blacklist)
# --------------------------------------------------------------------------- #
@pytest.mark.django_db
def test_a5_logout_blacklistea_refresh_del_dispositivo(zk_user):
    refresh = RefreshToken.for_user(zk_user.user)
    jti = refresh["jti"]
    assert not BlacklistedToken.objects.filter(token__jti=jti).exists()

    # El logout lee el refresh de la cookie HttpOnly (paso 8) y lo invalida.
    request = RequestFactory().post("/auth/logout/")
    request.COOKIES[settings.JWT_AUTH_REFRESH_COOKIE] = str(refresh)

    revoked = SecureLogoutView()._revoke_refresh_tokens(request, zk_user.user)
    assert revoked == 1, "El logout debe invalidar el refresh de este dispositivo."
    assert BlacklistedToken.objects.filter(token__jti=jti).exists()

    # Reutilizar el refresh ya invalidado no vale: check_blacklist lanza.
    with pytest.raises(TokenError):
        RefreshToken(str(refresh)).check_blacklist()


@pytest.mark.django_db
def test_a5_logout_no_invalida_refresh_ajeno(zk_user, django_user_model):
    other = django_user_model.objects.create_user(
        username="a5_other", email="a5_other@example.test", password="Wren$Kilo7pluto"
    )
    other_refresh = RefreshToken.for_user(other)
    jti = other_refresh["jti"]

    # zk_user "cierra sesión" enviando el refresh de OTRO usuario.
    request = RequestFactory().post("/auth/logout/")
    request.COOKIES[settings.JWT_AUTH_REFRESH_COOKIE] = str(other_refresh)

    SecureLogoutView()._revoke_refresh_tokens(request, zk_user.user)

    # La comprobación de propiedad (user_id) impide invalidar el token ajeno.
    assert not BlacklistedToken.objects.filter(token__jti=jti).exists(), (
        "Un usuario no debe poder invalidar el refresh token de otro."
    )


# --------------------------------------------------------------------------- #
# A6-a — señuelo Argon2 para usuario inexistente (contra temporización)
# --------------------------------------------------------------------------- #
@pytest.mark.django_db
def test_a6a_dummy_hasher_argon2_para_usuario_inexistente(monkeypatch):
    from django.contrib.auth.hashers import Argon2PasswordHasher

    from myapp.authentication import EmailBackend

    calls = []
    real_encode = Argon2PasswordHasher.encode

    def spy_encode(self, password, salt):
        calls.append(password)
        return real_encode(self, password, salt)

    monkeypatch.setattr(Argon2PasswordHasher, "encode", spy_encode)

    backend = EmailBackend()
    result = backend.authenticate(
        None, email="noexiste_a6@example.test", password="Decoy$Hash12abc"
    )

    assert result is None
    assert calls, (
        "Con un usuario inexistente, EmailBackend debe ejecutar el hasher Argon2 "
        "(señuelo, A6): mismo coste que un usuario real → no delata su existencia "
        "por temporización. Y el señuelo es Argon2, igual que los usuarios reales."
    )
