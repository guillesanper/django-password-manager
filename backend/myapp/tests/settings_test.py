"""Settings de test de L1 — hereda de producción y toca SÓLO cinco cosas (§6).

    from demo.settings import *

Los tests corren contra la MISMA Redis y el MISMO MinIO que la app en marcha, y los
middleware escriben en ambos en cada petición. Este módulo aísla el daño sin cambiar
la semántica de seguridad que se está probando. Las cinco cosas, y NADA más:

  1. Redis a la db 15 + KEY_PREFIX='test' en `default` Y en `sessions`. Las cachés
     reales son db 1 y db 2 de la misma instancia (ver CACHES en demo/settings.py):
     sin esto, un test de rate limit escribe en los contadores de la app viva y un
     `cache.clear()` le borra la sesión a un usuario real.
  2. Bucket MinIO propio (MINIO_BUCKET_NAME='test-…'): si no, los tests de ficheros
     dejan objetos con claves de test en el bucket de producción, indistinguibles de
     los buenos.
  3. Handlers de fichero del LOGGING → NullHandler. Los RotatingFileHandler apuntan a
     rutas RELATIVAS (infrastructure/logs/django/*.log): con otro cwd el logging
     revienta al configurarse y la suite entera falla por una razón ajena (hecho 7).
  4. DEBUG=False fijo, para que ninguna aserción dependa de con qué pila se lanzó.
  5. Nada más.

REGLA DURA (§6): los tests que AFIRMAN sobre configuración (A8-a, C6-LEEWAY, M6, BL1)
importan `demo.settings` EXPLÍCITAMENTE, nunca `django.conf.settings` —que ya viene
tocado por este módulo—. Si M6 leyera django.conf.settings comprobaría el override del
test, no producción. (Los tests de AISLAMIENTO de esta tanda sí leen django.conf.settings
a propósito: quieren verificar que estos overrides se aplicaron.)
"""

import re

from demo.settings import *  # noqa: F401,F403


# --- 1. Redis a la db 15, KEY_PREFIX='test' (default Y sessions) -------------
def _redis_url_to_db15(url: str) -> str:
    """Reapunta la db de una URL redis://…/<n> a la 15, conservando host/credenciales."""
    if re.search(r"/\d+$", url):
        return re.sub(r"/\d+$", "/15", url)
    return url.rstrip("/") + "/15"


for _cache_name in ("default", "sessions"):
    _cache = CACHES[_cache_name]  # noqa: F405
    _cache["LOCATION"] = _redis_url_to_db15(_cache["LOCATION"])
    _cache["KEY_PREFIX"] = "test"


# --- 2. Bucket MinIO propio --------------------------------------------------
# 'test-' delante del bucket real (no lo sustituye del todo: conserva la raíz para
# que sea legible de dónde salió). La app usa 'user-encrypted-files'.
MINIO_BUCKET_NAME = "test-" + MINIO_BUCKET_NAME  # noqa: F405


# --- 3. Handlers de fichero del LOGGING → NullHandler ------------------------
# Cualquier handler basado en fichero (RotatingFileHandler / FileHandler, o que
# declare `filename`) se sustituye por un NullHandler. `console` (StreamHandler) se
# conserva. Los loggers siguen refiriéndose a los mismos nombres de handler.
for _hname, _hcfg in list(LOGGING.get("handlers", {}).items()):  # noqa: F405
    if "FileHandler" in _hcfg.get("class", "") or "filename" in _hcfg:
        LOGGING["handlers"][_hname] = {"class": "logging.NullHandler"}  # noqa: F405


# --- 4. DEBUG=False fijo -----------------------------------------------------
DEBUG = False


# --- 5. Nada más -------------------------------------------------------------
