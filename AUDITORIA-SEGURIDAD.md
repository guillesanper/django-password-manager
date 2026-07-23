# Auditoría de seguridad — Gestor de Contraseñas

**Proyecto:** Django 5.1 + DRF + JWT / React-Vite / PostgreSQL / Redis / MinIO / Docker
**Rama auditada:** `tokens` (último commit previo a la intervención: `add989a`)
**Fecha:** 21 de julio de 2026 (actualizado el 23 de julio de 2026)
**Estado:** Fase 0 aplicada. **Fase 1 (endurecimiento de la superficie web) aplicada,
sin commitear y sin verificar en contenedor** — sólo verificación estática. Fases 2–3
pendientes.

> **Aviso de estado (23 jul 2026).** Todo lo que este documento marca como aplicado en la
> Fase 1 se ha comprobado **sólo de forma estática** (`py_compile`, `tsc --noEmit`, `nginx
> -t`, pruebas en aislado del código real con dobles). **La pila no se ha levantado ni una
> vez** desde que empezó la Fase 1. Los criterios de aceptación que requieren
> `docker compose up` (§10) siguen pendientes. Nada de la Fase 1 está commiteado: los
> commits los gestiona el usuario.

---

## 1. Lo que la Fase 0 NO arregla

> ### ⚠️ Después de la Fase 0 esto **sigue sin ser un gestor de contraseñas seguro**.
>
> El servidor continúa pudiendo **descifrar todas las bóvedas de todos los usuarios sin
> conocer ninguna contraseña maestra**. Quien lea la base de datos —un volcado, una copia
> de seguridad, un administrador, un atacante con acceso a Postgres— obtiene todas las
> contraseñas y todos los ficheros en claro. La contraseña maestra es hoy un control de
> acceso decorativo, no un secreto criptográfico.
>
> Eso **no se corrige hasta la Fase 2**, que es una rearquitectura completa a
> zero-knowledge. La Fase 0 no es una solución: es cortar el sangrado.

Lo que la Fase 0 sí consigue:

- Esa capacidad de descifrado **ya no se filtra por los logs** (la clave se imprimía por
  stdout en cada verificación) ni por un **endpoint que la ejercía sin pedir la maestra**.
- Nadie puede **falsificar JWT** con la `SECRET_KEY` por defecto que estaba en el código.
- **Postgres, Redis, MinIO, Grafana y Prometheus dejan de estar publicados** en el host con
  credenciales conocidas o sin credencial alguna.
- El servidor deja de ejecutarse con `runserver` y `DEBUG=True`.

### Balance por severidad

De los **6 hallazgos críticos**, la Fase 0 cierra **2**, contiene **1** y deja **3** intactos:

| ID | Hallazgo | Estado tras Fase 0 |
|----|----------|--------------------|
| **C1** | `hashed_key` no es un hash: es la clave de cifrado | ❌ **Intacto** — fallo raíz, Fase 2 |
| **C2** | Salt global, constante y publicada en git | ❌ **Intacto** — Fase 2 |
| **C3** | `/api/security/analysis/` descifra sin la maestra | ⚠️ **Contenido**, no arreglado |
| **C4** | Secretos impresos por stdout | ✅ **Cerrado** |
| **C5** | `SECRET_KEY` por defecto y `DEBUG=True` hardcodeado | ✅ **Cerrado** |
| **C6** | Cifrado sin autenticar (AES-CFB / ChaCha20 sin MAC) | ❌ **Intacto** — Fase 2 |

C3 está **contenido, no arreglado**: el endpoint devuelve 501, pero la capacidad que
explotaba —que el servidor pueda descifrar sin la maestra— sigue ahí, y sigue estando al
alcance de cualquier otra ruta que la use.

---

## 2. Estado de los 30 hallazgos

Severidad: **C** = crítico (explotable hoy, compromete todas las bóvedas), **A** = alto,
**M** = medio.

| ID | Hallazgo | Sev. | Estado | Cierra en |
|----|----------|------|--------|-----------|
| C1 | `hashed_key` es la clave de cifrado, no un hash | C | ❌ Abierto | Fase 2 |
| C2 | Salt global constante, en git | C | ❌ Abierto | Fase 2 |
| C3 | Bypass completo de la clave maestra | C | ⚠️ Contenido | Fase 2 |
| C4 | Secretos y metadatos por stdout | C | ✅ Cerrado | **Fase 0** |
| C5 | `SECRET_KEY` por defecto + `DEBUG=True` | C | ✅ Cerrado | **Fase 0** |
| C6 | Cifrado sin autenticar; `LEEWAY` de 300 s | C | ⚠️ AEAD abierto (Fase 2); **LEEWAY 30 s ✅ Fase 1** | Fase 2 |
| A1 | JWT en `localStorage`/`sessionStorage` | A | ✅ **Cerrado (Fase 1, paso 8)** | Fase 1 |
| A2 | Sin CSP; cookies sin `HttpOnly` | A | ✅ **Cerrado (Fase 1, pasos 8 y 9)** | Fase 1 |
| A3 | Fuerza bruta ilimitada de la maestra | A | ✅ **Cerrado (Fase 1, paso 11)** | Fase 1 |
| A4 | `X-Forwarded-For` sin validar (**10** copias) | A | ✅ **Cerrado (Fase 1, paso 10)** | Fase 1 |
| A5 | Logout no invalida el refresh token | A | ✅ **Cerrado (Fase 1, pasos 12 y 8)** | Fase 1 |
| A6 | Enumeración de usuarios por temporización | A | ✅ **Cerrado (Fase 1, paso 13)** | Fase 1 |
| A7 | `/api/accounts/` devuelve la bóveda cifrada entera | A | ❌ Abierto | Fase 2 |
| A8 | PBKDF2 con 100 000 iteraciones; sin Argon2 | A | ⚠️ **Argon2 para cuentas ✅ Fase 1 (paso 14)**; iteraciones de bóveda: Fase 2 | Fase 1/2 |
| A9 | Las bóvedas privadas no protegen nada | A | ❌ Abierto | Fase 2 |
| A10 | Infraestructura expuesta con credenciales por defecto | A | ✅ Cerrado | **Fase 0** |
| A11 | `runserver` en producción, `DEBUG=1`, volumen de código | A | ✅ Cerrado | **Fase 0** |
| A12 | Nginx sin TLS, sin cabeceras, sin `limit_req` | A | ✅ **Cerrado (Fase 1, paso 16)** | Fase 1 |
| M1 | `str(e)` devuelto al cliente | M | ✅ **Cerrado (Fase 1, paso 15)** | Fase 1 |
| M2 | `ENCRYPTION_KEY` efímera por proceso | M | ✅ Cerrado *hacia delante* | **Fase 0** |
| M3 | DoS aplicativo (generador y subida de ficheros) | M | ⚠️ **Generador acotado ✅ Fase 1 (paso 17)**; streaming de subida: Fase 3 | Fase 1/3 |
| M4 | `Content-Type` de descarga controlado por el usuario | M | ❌ Abierto | Fase 3 |
| M5 | CVEs conocidos en dependencias | M | ❌ Abierto | Fase 3 |
| M6 | `IGNORE_EXCEPTIONS: True` → seguridad *fail-open* | M | ✅ **Cerrado (Fase 1, paso 19)** | Fase 1 |
| M7 | Código muerto/roto (`api_unlock_all_accounts`, …) | M | ⚠️ `upload_file_combined` (GET→POST) ✅ adelantado en Fase 1; resto: Fase 3 | Fase 3 |
| M8 | Imposible rotar la clave maestra | M | ❌ Abierto | Fase 2 |
| M9 | Sin MFA ni verificación de email | M | ❌ Abierto | Fase 3 |
| M10 | `getattr("settings", …)` sobre la cadena literal | M | ❌ Abierto | Fase 3 |
| M11 | Comparación de secretos con `==` | M | ✅ Cerrado | **Fase 0** |
| M12 | `SecurityLoggingMiddleware` bloquea por subcadenas | M | ✅ **Cerrado (Fase 1, paso 18)** | Fase 1 |

Además se corrigieron en la Fase 0 dos **bugs laterales** detectados durante la auditoría,
sin identificador propio: la caché `sessions` compartía base de datos Redis con la caché
general, y `SESSION_ENCRYPTION_KEY` reutilizaba `ENCRYPTION_KEY`. Ver §7.

---

## 3. Hallazgos críticos en detalle

### C1 — `MasterKey.hashed_key` no es un hash: es la clave de cifrado real ❌ ABIERTO

**Ubicación:** [backend/myapp/models.py](backend/myapp/models.py) (`MasterKey`),
[password_views.py](backend/myapp/views/password_views.py),
[file_views.py](backend/myapp/views/file_views.py)

El campo `hashed_key` almacena, en base64, **la clave derivada real**, y es exactamente ese
valor el que se pasa como clave de cifrado en todo el código
(`master_key_entry.hashed_key.encode()`). No hay hash en ninguna parte del flujo.

Consecuencias:

- Quien lea la base de datos descifra **todas** las contraseñas y ficheros de **todos** los
  usuarios. No hace falta romper nada: la clave está ahí, en claro.
- `verify_master_key` compara la clave derivada del intento **contra el mismo valor que usa
  para descifrar**. Es decir, la "verificación de la contraseña maestra" y la "clave de
  cifrado" son el mismo secreto, lo que convierte cualquier endpoint que verifique la
  maestra en un oráculo de descifrado.
- Un volcado de `pg_dump`, una copia de seguridad, un administrador de base de datos o un
  atacante con acceso de lectura a Postgres comprometen el sistema entero.

**Este es el fallo raíz.** Todo lo demás del sistema —rate limiting, sesiones avanzadas,
auditoría, doble cifrado de ficheros— está construido encima de él y no aporta protección
real mientras siga presente.

### C2 — Salt global, constante y publicada en git ❌ ABIERTO

**Ubicación:** [backend/myapp/models.py](backend/myapp/models.py),
`backend/myapp/migrations/0007_*.py` … `0021_*.py`

El campo usa `default=get_random_string(32)`. Esa expresión **se evalúa una sola vez, al
importar el módulo**, no por cada fila. El valor resultante queda congelado en la migración
que lo introdujo, y la migración está versionada.

Verificado durante la auditoría: **no hay una sal, hay ~15 sales congeladas** en las
migraciones `0007` a `0021`, todas en el repositorio. La última, en `0021_*.py`, es
`o1XeSHppaj2ijlX1uDlIJIBO6dUV7B82`.

Consecuencia: todos los usuarios comparten la misma sal de derivación **y esa sal es
pública**. Un único ataque de diccionario precalculado rompe a toda la base de usuarios a
la vez. La sal deja de cumplir su única función, que es impedir precisamente eso.

### C3 — Bypass completo de la clave maestra ⚠️ CONTENIDO EN FASE 0

**Ubicación:** [backend/myapp/views/security_views.py](backend/myapp/views/security_views.py)

Eran **dos** endpoints, no uno:

1. **`api_security_analysis`** (`GET /api/security/analysis/`) — descifraba **la bóveda
   entera sin pedir la contraseña maestra**, tomando `hashed_key` directamente de la base de
   datos. Un access token robado por XSS o phishing bastaba para volcar todas las
   contraseñas del usuario en claro, en una sola petición GET.
2. **`api_check_single_password_breach`** (`POST`) — sí exige `master_password`, pero
   `verify_master_key` compara contra el mismo valor que después usa para descifrar (C1), y
   `/api/security/` está clasificado como `data` en
   [middleware.py](backend/myapp/middleware.py) = **sin rate limiting**. Resultado: un
   oráculo de fuerza bruta ilimitada contra la clave maestra.

El primero es la prueba directa de C1: si la aplicación puede descifrar sin la maestra, la
maestra no protege nada.

**Contención aplicada:** ambos devuelven `501` con `code: FEATURE_SUSPENDED`. El código
original se conserva debajo como código muerto explícito, porque en la Fase 2 se reutilizan
`calculate_password_entropy`, `check_password_breach_sync` (la implementación de
k-anonimato contra HaveIBeenPwned es **correcta** y sólo cambia de lado) y
`analyze_password_patterns`.

**Por qué "contenido" y no "cerrado":** la capacidad que estos endpoints ejercían sigue
existiendo. Desaparece por construcción cuando el servidor deje de poder descifrar (Fase 2).

### C4 — Secretos y metadatos impresos por stdout ✅ CERRADO EN FASE 0

**Ubicación:** [models.py](backend/myapp/models.py), [file_views.py](backend/myapp/views/file_views.py) y 5 ficheros más

`verify_master_key` contenía `print(f"Derived Key: {derived_key_str}")` y
`print(f"Stored Hashed Key: …")`: **la clave de cifrado del usuario volcada a los logs de
Docker en cada verificación de contraseña maestra**. Cualquiera con acceso a
`docker compose logs`, a un agregador de logs o a un backup de logs obtenía las claves.

Además había **65 `print()`** repartidos por las vistas que filtraban rutas, nombres de
fichero, tamaños, identificadores y trazas completas (metadatos y PII, no secretos).

**Corregido:** eliminados los dos `print` de material criptográfico; los 65 restantes
convertidos a `logger.debug/warning/error`, y los que estaban en bloques `except` a
`logger.exception` (que ya adjunta la traza). Eliminados también los 6 pares
`import traceback` + `traceback.print_exc()` de `file_views.py`.

Verificado: 0 ocurrencias de `print(` y de `traceback.print_exc` en `myapp/views/`,
`models.py`, `encryption_utils.py`, `middleware.py` y `demo/`.

### C5 — `SECRET_KEY` por defecto y `DEBUG=True` hardcodeado ✅ CERRADO EN FASE 0

**Ubicación:** [backend/demo/settings.py](backend/demo/settings.py)

- `SECRET_KEY = os.getenv("DJANGO_SECRET_KEY", "django-insecure-replace-this-in-production")`
  — y la variable **nunca estuvo definida**, así que el valor efectivo era el fallback
  público. `SECRET_KEY` firma los JWT con `HS256`: **cualquiera que leyese el repositorio
  podía falsificar un token de cualquier usuario.**
- `DEBUG = True` **hardcodeado**, no leído del entorno. El `DEBUG=1` de `docker-compose.yml`
  no hacía nada en absoluto (`settings.py` nunca consultaba `os.getenv("DEBUG")`), lo cual
  es peor: daba una falsa sensación de estar controlado por entorno.
- `CORS_ALLOWED_ORIGINS` y `CSRF_TRUSTED_ORIGINS` de producción apuntaban a `tudominio.com`,
  un marcador de posición.
- `ALLOWED_HOSTS` incluía `0.0.0.0`, que no es un host válido sino una dirección de escucha.

**Corregido:** ver §7 (F0-4 y F0-5).

### C6 — Cifrado sin autenticar ❌ ABIERTO (AEAD) · ✅ LEEWAY cerrado en Fase 1

**Ubicación:** [backend/myapp/encryption_utils.py](backend/myapp/encryption_utils.py)

Se usan **AES-CFB y ChaCha20 en crudo, sin MAC ni AEAD**. Consecuencias:

- El ciphertext es **maleable**: en modo CFB un atacante con acceso de escritura a la base
  de datos puede voltear bits concretos del texto claro de forma dirigida.
- **No hay detección de manipulación**: alterar un byte no produce error, produce basura.
- Una clave incorrecta **no falla**: devuelve bytes sin sentido silenciosamente. Esto además
  enmascara errores de clave como si fueran corrupción de datos.

Adicionalmente, `SIMPLE_JWT` fija `LEEWAY: 300`, que **amplía en 5 minutos la ventana de
validez de un token ya expirado**. **Bajado a 30 s en la Fase 1 (paso 12).** El cifrado sin
autenticar (AEAD) sigue abierto y es Fase 2.

---

## 4. Hallazgos altos en detalle

### A1 — JWT en `localStorage` y `sessionStorage` ✅ CERRADO EN FASE 1 (paso 8)
[frontend/src/services/authService.ts](frontend/src/services/authService.ts) — Access y
refresh (7 días) guardados en almacenamiento accesible desde JavaScript. Cualquier XSS =
robo de sesión persistente durante una semana. Se combina de forma directa con A2 (sin CSP)
y con A7 (la bóveda cifrada completa disponible en un solo endpoint).

### A2 — Sin CSP y cookies legibles desde JS ✅ CERRADO EN FASE 1 (pasos 8 y 9)
[backend/demo/settings.py](backend/demo/settings.py) — `django-csp` **está en
`requirements.txt` pero no en `MIDDLEWARE`**: no hay ninguna política de contenido.
`SESSION_COOKIE_HTTPONLY = False` y `CSRF_COOKIE_HTTPONLY = False`. Un XSS no encuentra
ninguna mitigación.

### A3 — Fuerza bruta ilimitada de la contraseña maestra ✅ CERRADO EN FASE 1 (paso 11)
[backend/myapp/middleware.py](backend/myapp/middleware.py),
[backend/myapp/urls.py](backend/myapp/urls.py)

`RateLimitMiddleware.classify_endpoint` sólo trata como sensible `/api/master-key/verify/`.
Las demás rutas que **también validan la contraseña maestra** se clasifican como `data` o
`normal`, es decir **sin límite alguno**: `/api/unlock-password/…`, `/passwords/add/`,
`/passwords/<id>/delete/`, `/api/files/<id>/download/`, `/api/batch-delete-passwords/`.

La Fase 0 eliminó uno de esos oráculos (`/api/security/`, ver C3), pero **el resto siguen
abiertos**. Cierre real en la Fase 1, paso 11.

### A4 — `X-Forwarded-For` aceptado sin validar ✅ CERRADO EN FASE 1 (paso 10)
[middleware.py](backend/myapp/middleware.py),
[auth_views.py](backend/myapp/views/auth_views.py) y 5 ficheros más — **siete
implementaciones duplicadas** de `get_client_ip`, todas confiando en la cabecera sin
comprobar que venga de un proxy conocido. Un atacante que rote la cabecera evade el rate
limiting, el bloqueo de cuenta y el bloqueo de IP sospechosa, y además **envenena**
`SecurityEvent` y `ActivityLog`, que son las únicas fuentes de evidencia forense.
Combinado con M12, permite **bloquear la IP de un tercero** (auto-DoS).

### A5 — El logout no invalida el refresh token ✅ CERRADO EN FASE 1 (pasos 12 y 8)
[auth_views.py](backend/myapp/views/auth_views.py) — `token_blacklist` está instalado y
`ROTATE_REFRESH_TOKENS` activo, pero el logout no llama a `.blacklist()`. Tras "cerrar
sesión" el refresh token sigue siendo válido **7 días**.

### A6 — Enumeración de usuarios por temporización ✅ CERRADO EN FASE 1 (paso 13)
[backend/myapp/authentication.py](backend/myapp/authentication.py) — `EmailBackend` retorna
inmediatamente en `User.DoesNotExist` **sin ejecutar el hasher**, eliminando la
contramedida que `ModelBackend` sí implementa. La diferencia de latencia entre un email
existente y uno inexistente es medible y permite construir listas para phishing dirigido.

### A7 — La bóveda cifrada completa en cada petición ❌ ABIERTO
[password_views.py](backend/myapp/views/password_views.py) — `/api/accounts/` devuelve
`encrypted_password`, `encrypted_key`, `iv_or_nonce` y `salt` de toda la bóveda. Con la sal
pública de C2, esto es material suficiente para un ataque offline.

### A8 — Derivación de claves insuficiente ⚠️ PARCIAL (Argon2 para cuentas en Fase 1, paso 14; bóveda en Fase 2)
[encryption_utils.py](backend/myapp/encryption_utils.py),
[models.py](backend/myapp/models.py) — PBKDF2-SHA256 con **100 000 iteraciones** en las
cinco derivaciones del código (OWASP 2023 recomienda 600 000). `argon2-cffi` está instalado
pero `PASSWORD_HASHERS` no se configura, así que Django usa PBKDF2 por defecto también para
las contraseñas de cuenta.

### A9 — Las bóvedas privadas no protegen nada ❌ ABIERTO
[password_views.py](backend/myapp/views/password_views.py) — `vault_already_unlocked` es un
**booleano enviado por el cliente** que salta la verificación, y `api_vault_passwords` lista
el contenido de una bóveda privada sin pedir su contraseña.

### A10 — Infraestructura expuesta con credenciales por defecto ✅ CERRADO EN FASE 0
[backend/docker-compose.yml](backend/docker-compose.yml) — Postgres (`myuser`/`password`),
Redis **sin autenticación**, MinIO y Grafana (`admin`/`secure_grafana_2024`) publicaban
puertos al host: 5432, 6379, 9000, 9001, 3000, 9090 y 8080. Todas esas credenciales estaban
en git. El `webhook-collector` llevaba además la URL de Postgres con la contraseña en claro.
Ver §7 (F0-5, F0-6).

### A11 — `runserver` como servidor de producción ✅ CERRADO EN FASE 0
[Dockerfile](backend/Dockerfile), [docker-compose.yml](backend/docker-compose.yml) —
`runserver` en el `CMD` y en el `command`, `DEBUG=1` en compose y volumen `.:/usr/src/app`
montando el código fuente sobre la imagen. `gunicorn` estaba en `requirements.txt` sin
usarse. Ver §7 (F0-7).

### A12 — Nginx sin TLS ni cabeceras ni límites ✅ CERRADO EN FASE 1 (paso 16)
[backend/infrastructure/nginx/nginx.conf](backend/infrastructure/nginx/nginx.conf) — sólo
`listen 80`; el directorio `ssl` se monta pero no se usa. Sin cabeceras de seguridad, sin
`limit_req` (nada frena un DDoS de capa 7), sin `client_max_body_size`, y publicando la
consola de MinIO.

---

## 5. Hallazgos medios en detalle

| ID | Hallazgo | Detalle |
|----|----------|---------|
| **M1** ✅ | Fuga de detalles internos | **Cerrado en Fase 1 (paso 15):** 31 fugas → `logger.exception` + mensaje genérico, conservando `error` y el estado. Incluye la frontera con `minio_service.py`. Ver §7·bis. |
| **M2** ✅ | `ENCRYPTION_KEY` efímera | Ver §6, hecho 2. Cerrado *hacia delante*. |
| **M3** ⚠️ | DoS aplicativo | **Generador acotado en Fase 1 (paso 17)**: `count ∈ [1,20]`, `length ∈ [8,128]`, `_bounded_int` → 400 en vez de 500. La subida que se lee íntegra y se cifra dos veces en RAM sigue abierta (streaming: Fase 3). Trampa: el endpoint acotado no lo llama nadie (corrección 12). |
| **M4** ❌ | `Content-Type` controlado por el usuario | El tipo de la descarga se deriva del nombre del fichero subido (`text/html`, `image/svg+xml` incluidos) → XSS almacenado si algún flujo lo sirve inline. |
| **M5** ❌ | CVEs en dependencias | `cryptography==41.0.7`, `Django==5.1` (sin parches 5.1.x), `requests==2.31.0`, `urllib3==2.0.7`. Sin fijado de hashes ni escaneo en CI. |
| **M6** ✅ | Seguridad *fail-open* | **Cerrado en Fase 1 (paso 19):** `IGNORE_EXCEPTIONS: False` + `cache_utils.py` con política explícita por uso (`strict_*` deniega con 503; `lenient_*` observa y sigue) + timeouts de socket a 2 s. Ver §7·bis. |
| **M7** ⚠️ | Código muerto/roto | `upload_file_combined` (`@api_view(['GET'])` que leía `request.FILES`) **corregido a POST en Fase 1** (adelantado). `api_unlock_all_accounts` sigue siendo GET con guarda → 405 siempre, y su `decrypt_password` con argumentos desplazados: Fase 3. |
| **M8** ❌ | Imposible rotar la clave maestra | `change_master_key` devuelve 501. Tras un incidente **no hay forma de rotar**. |
| **M9** ❌ | Sin MFA ni anti-phishing | `TRUSTED_DEVICES.REQUIRE_2FA_FOR_NEW_DEVICES` existe en settings pero **no hay implementación**. Sin verificación de email en el registro, sin aviso por correo de login desde dispositivo nuevo. |
| **M10** ❌ | `getattr` sobre una cadena literal | `getattr("settings", 'SESSION_COOKIE_SECURE', True)` en `middleware.py`: se hace `getattr` sobre la cadena `"settings"`, no sobre el módulo, así que **siempre devuelve el default**. |
| **M11** ✅ | Comparación de secretos con `==` | Cerrado en Fase 0 con `hmac.compare_digest`. Ver §7 (F0-1). |
| **M12** ✅ | Bloqueo por subcadenas | **Cerrado en Fase 1 (paso 18):** detección sólo por ruta y método, umbral 12 sondeos/10 min → 403 15 min, User-Agent sólo registra. Era peor de lo descrito (correcciones 9 y 10). Ver §7·bis. |

---

## 6. Hechos verificados durante la auditoría

Estos doce puntos se comprobaron sobre el código y el entorno reales. Varios contradicen lo
que sugería una lectura superficial, y condicionan el orden de la remediación.

1. **`backend/.env` no existía** y el `.env` de la raíz estaba **vacío (0 bytes)**. Toda la
   configuración "por entorno" caía en sus valores por defecto.

2. **`ENCRYPTION_KEY` nunca estuvo definida.** Al arrancar, Django emitía
   `WARNING security Generated new system encryption key`, y
   [minio_service.py](backend/myapp/minio_service.py) generaba una clave Fernet **efímera
   por proceso**. Consecuencia: **lo ya subido a MinIO es irrecuperable desde el primer
   reinicio** (M2 ya consumado, no prevenible). Definirla ahora arregla el problema hacia
   delante y es **prerrequisito duro del multi-worker de gunicorn** — con 3 workers y sin
   ella, cada worker cifraría con una clave distinta y los ficheros se perderían de
   inmediato. Por eso F0-5 debe ir obligatoriamente antes que F0-7.

3. **`manage.py check` no se puede ejecutar fuera de Docker**: `minio_service.py` instancia
   `MinIOService()` **a nivel de módulo**, lo que bloquea ~20 s reintentando resolver el
   host `minio`. Toda verificación tiene que hacerse dentro del contenedor.

4. **No hay datos reales, ni dominio, ni certificados TLS.** Rotar los secretos no tiene
   coste operativo; se acepta la ruptura de datos para migrar a zero-knowledge.

5. **El salt global no es uno, son ~15** (ver C2), congelados en las migraciones `0007` a
   `0021`, todos en git.

6. **La ruta `/` servida por Django ya estaba rota**, con independencia de la Fase 0:
   `DJANGO_VITE_ASSETS_PATH` apunta a `backend/static/dist` pero Vite compila a
   `<raíz>/static/dist`, y **ninguno de los dos directorios existe**. Además
   `DJANGO_VITE_DEV_SERVER_PORT = 5173` frente al Vite real en **5174**. La aplicación se
   usa directamente en `localhost:5174` contra `localhost:8000`, hardcodeado en 8 servicios
   de `frontend/src/services/*.ts`. Con `DEBUG=False` el síntoma pasa de página en blanco a
   error 500. **Arreglarlo es Fase 1, no Fase 0.**

7. **`infrastructure/logs/` no está en git** y `LOGGING` escribe en **rutas relativas**
   (`infrastructure/logs/django/*.log`), es decir en
   `/usr/src/app/infrastructure/logs/django/`. Ese directorio existía **sólo de rebote, por
   el volumen `.:/usr/src/app`**; el volumen declarado apuntaba a `/var/log/django`, que no
   usa nadie. ⚠️ **Quitar el volumen sin corregir esto impide que Django arranque**:
   `RotatingFileHandler` no crea el directorio. Por eso F0-7 añade el `mkdir` al Dockerfile
   y remapea el volumen de logs.

8. **Consumidores de los endpoints suspendidos** (búsqueda exhaustiva en `frontend/src`):
   `SecurityPage.tsx` → `getSecurityAnalysis()` es el **único consumidor real**, y ya tiene
   `try/catch` con objeto de fallback en `securityService.ts`, así que la página no revienta:
   muestra su banner de error genérico y las tarjetas de sesiones siguen cargando.
   `checkPasswordBreach()` y `getSecurityRecommendations()` están definidos **sin ningún
   llamador**. `/api/dashboard/security-summary/` **no descifra**, así que no se toca.

9. **No hacía falta ninguna dependencia nueva** en Fase 0: `gunicorn==21.2.0`, `whitenoise`,
   `django-csp` y `argon2-cffi` ya estaban en `requirements.txt` (los dos últimos, sin usar).

10. **Trampas de la rotación de credenciales sobre volúmenes ya existentes:**
    - `POSTGRES_PASSWORD` **sólo se aplica en el `initdb`**. Sobre un volumen ya creado hay
      que ejecutar `ALTER USER … WITH PASSWORD …` o Django deja de conectar. Se decidió
      **conservar el nombre `myuser` y rotar sólo la contraseña**.
    - `GF_SECURITY_ADMIN_PASSWORD` se comporta igual → `grafana-cli admin reset-admin-password`.
    - **MinIO sí relee** sus credenciales root en cada arranque: rotarlas es reiniciar.

11. **Bug lateral:** la caché `sessions` hacía `os.getenv('REDIS_URL', 'redis://redis:6379/2')`.
    Como `REDIS_URL` sí estaba definida, el default nunca se usaba y **ambas cachés
    compartían la base de datos 1** de Redis. Corregido con `REDIS_SESSIONS_URL`.

12. **Sólo `models.py` volcaba material criptográfico.** Los `print` de `file_views.py`
    imprimían longitudes, títulos y rutas: metadatos y PII, graves pero no secretos.

---

## 7. Cambios aplicados en la Fase 0

Orden de ejecución (de menor a mayor riesgo), con verificación tras cada paso. Dos
desviaciones deliberadas respecto al plan original: **F0-6 antes que F0-5** (cerrar puertos
es reversible en segundos y reduce la ventana durante la rotación) y **F0-5
obligatoriamente antes que F0-7** (ver hecho 2).

### F0-1 · `models.py` — eliminar el volcado de claves y comparar en tiempo constante
**Cierra C4 (parcial) y M11.** [backend/myapp/models.py](backend/myapp/models.py)

- Eliminadas las dos líneas `print(f"Derived Key: …")` y `print(f"Stored Hashed Key: …")` de
  `verify_master_key`.
- Añadido `import hmac`.
- `verify_master_key` → `return hmac.compare_digest(derived_key_str, self.hashed_key)`.
- `Vault.verify_vault_password` → `return hmac.compare_digest(expected_hash, self.vault_password_hash)`.

> `hmac.compare_digest` (M11) se adelantó desde la Fase 1 por ser un cambio de una línea sin
> riesgo. Nota importante: **compara en tiempo constante un secreto que no debería existir**.
> Mitiga el canal lateral de temporización, no el problema de fondo (C1).

### F0-2 · 65 `print()` → `logger`
**Cierra C4 en metadatos.** `file_views.py` (39), `password_views.py` (10),
`vault_views.py` (6), `masterkey_views.py` (4), `security_views.py` (3),
`dashboard_views.py` (1), `encryption_utils.py` (2).

A cada fichero se le añadió `import logging` + `logger = logging.getLogger(__name__)`.
Los `[DEBUG]/[ERROR]/[WARNING]` pasaron a `logger.debug/error/warning` sin la etiqueta; los
`print` dentro de `except` con `{e}` pasaron a `logger.exception`; se eliminaron los 6 pares
`import traceback` + `traceback.print_exc()` de `file_views.py`, fundidos en el
`logger.exception` correspondiente.

### F0-3 · Suspender el bypass de la clave maestra
**Contiene C3, reduce A3.** [backend/myapp/views/security_views.py](backend/myapp/views/security_views.py)

`api_security_analysis` y `api_check_single_password_breach` devuelven ahora:

```python
return JsonResponse({
    'success': False,
    'error': 'El análisis de seguridad está temporalmente deshabilitado '
             'mientras se migra el cifrado a zero-knowledge.',
    'code': 'FEATURE_SUSPENDED',
}, status=501)
```

El código original se conserva íntegro debajo, como código muerto explícito, para
reutilizarlo en la Fase 2. **No se tocó el frontend**: `SecurityPage.tsx` ya degrada con
elegancia (hecho 8).

### F0-4 · `settings.py` gobernado por entorno
**Cierra C5.** [backend/demo/settings.py](backend/demo/settings.py)

```python
SECRET_KEY = os.environ["DJANGO_SECRET_KEY"]          # KeyError al arrancar si falta
DEBUG = _env_bool("DJANGO_DEBUG", "false")
ALLOWED_HOSTS = _env_list("DJANGO_ALLOWED_HOSTS", "localhost,127.0.0.1,web")   # sin 0.0.0.0
CORS_ALLOWED_ORIGINS = _env_list("CORS_ALLOWED_ORIGINS", "http://localhost:5174")
CSRF_TRUSTED_ORIGINS = _env_list("CSRF_TRUSTED_ORIGINS", "http://localhost:5174")
DJANGO_VITE_DEV_MODE = _env_bool("DJANGO_VITE_DEV_MODE", "false")
```

Eliminados el bloque `if DEBUG: … else: …` de CORS/CSRF (que apuntaba a `tudominio.com`) y
el `if not DEBUG:` de seguridad, sustituido por:

```python
_TLS = _env_bool("DJANGO_TLS_ENABLED", "false")   # TLS DESACOPLADO de DEBUG
SESSION_COOKIE_SECURE = _TLS
CSRF_COOKIE_SECURE = _TLS
if _TLS:
    SECURE_SSL_REDIRECT = True
    SECURE_HSTS_SECONDS = 31536000
    ...
```

> **Por qué el TLS va desacoplado de `DEBUG`, y por qué es crítico.** Con `not DEBUG` se
> activaría `SECURE_SSL_REDIRECT`. Pero nginx **no envía `X-Forwarded-Proto`** y sólo
> escucha en `:80`, sin certificados: Django nunca vería `https` y redirigiría en bucle
> infinito → **aplicación caída**. Y `SESSION_COOKIE_SECURE=True` sin TLS rompería
> `/admin/`. (La SPA no se vería afectada: autentica con JWT en la cabecera
> `Authorization`, no con cookie.) `DJANGO_TLS_ENABLED` pasa a `true` en la Fase 1, junto
> con el TLS de nginx.

También se eliminó `SECURE_FRAME_DENY`, que no es un ajuste válido de Django desde la 1.8;
la protección real la da `XFrameOptionsMiddleware`, ya presente, con `DENY` por defecto.

### F0-5 · `.env` real y rotación de todos los secretos
**Cierra C5 y A10; corrige M2 hacia delante.**

- Creado **`backend/.env`** (ignorado por git) con **todos los secretos rotados**.
- Creado **`backend/.env.example`** (versionado), sólo con placeholders y los comandos
  generadores en comentarios.
- `docker-compose.yml`: el servicio `web` pasa a `env_file: .env` en lugar de listar valores
  en claro; `db`, `minio`, `grafana` y `webhook-collector` interpolan desde `.env`.
- Se **eliminaron los defaults inseguros** de compose (`${MINIO_ROOT_USER:-admin_ultra_secure_2024}`,
  `${GRAFANA_ADMIN_PASSWORD:-secure_grafana_2024}`), sustituidos por la forma `${VAR:?mensaje}`
  para que el despliegue **falle en voz alta** en lugar de caer en una credencial pública.
- Redis pasa a `redis-server --requirepass ${REDIS_PASSWORD} …`, con healthcheck autenticado.
- Variables propias para `SESSION_ENCRYPTION_KEY` (antes caía en `ENCRYPTION_KEY`,
  reutilizando la misma clave para dos dominios distintos) y `REDIS_SESSIONS_URL` (hecho 11).

Generadores documentados en `.env.example`:

| Variable | Comando |
|----------|---------|
| `DJANGO_SECRET_KEY` | `python -c "from django.core.management.utils import get_random_secret_key as g; print(g())"` |
| `ENCRYPTION_KEY`, `SESSION_ENCRYPTION_KEY` | `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"` |
| resto | `python -c "import secrets; print(secrets.token_urlsafe(32))"` |

### F0-6 · Cerrar los puertos publicados
**Cierra A10.** [backend/docker-compose.yml](backend/docker-compose.yml)

Eliminados los bloques `ports:` de `db` (5432), `redis` (6379), `minio` (9000/9001),
`prometheus` (9090), `grafana` (3000) y `webhook-collector` (8080). Los servicios siguen
comunicándose por la red interna `app-network`.

Sólo publican al host **`nginx`** (80/443) y, **temporalmente, `web`** (8000), porque el
frontend de desarrollo apunta a `localhost:8000` hardcodeado en 8 servicios (hecho 6). Ese
puerto se retira cuando la Fase 1 arregle el enrutado.

Se comprobó que **no se usan URLs prefirmadas** de MinIO en ningún punto del backend, así
que cerrar 9000/9001 no rompe las descargas: Django habla con `minio:9000` por la red
interna.

### F0-7 · gunicorn y retirada del volumen de código
**Cierra A11.** [backend/Dockerfile](backend/Dockerfile), [backend/docker-compose.yml](backend/docker-compose.yml)

```dockerfile
RUN mkdir -p /usr/src/app/staticfiles \
    && mkdir -p /usr/src/app/static/dist \
    && mkdir -p /usr/src/app/collected_static \
    && mkdir -p /usr/src/app/infrastructure/logs/django     # ← imprescindible, hecho 7
```

En compose: eliminado `- .:/usr/src/app`, eliminado `DEBUG=1` (que no hacía nada), volumen
de logs remapeado a `./infrastructure/logs/django:/usr/src/app/infrastructure/logs/django`,
y `runserver` sustituido por gunicorn con `--workers 3 --timeout 120 --graceful-timeout 30
--max-requests 1000 --max-requests-jitter 100`.

Detalles que conviene no perder:

- **`--timeout 120`**, no el valor por defecto de 30 s: descargar y descifrar doblemente un
  fichero grande lo supera.
- **Aviso de memoria:** `file_views.py` lee el fichero entero y lo cifra dos veces en RAM
  (M3) → pico de ~300 MB **por worker** con un fichero de 100 MB. Bajar a `--workers 2` si
  el host va justo de memoria.
- El `command` de compose usa **forma de lista** (`sh -c` + bloque literal `|`), no el
  escalar plegado `>` del plan original: en YAML, dentro de un `>` las líneas *más
  indentadas* **conservan el salto de línea**, lo que habría partido los flags de gunicorn
  en comandos sueltos. Se usa además `exec` para que gunicorn quede como PID 1 y reciba
  `SIGTERM` correctamente.
- **Efecto colateral positivo:** `backend/staticfiles/` y `backend/static/` no existen en el
  host, así que el volumen de código estaba *ocultando* los directorios que el Dockerfile
  crea. Al quitarlo, `STATICFILES_DIRS` vuelve a apuntar a un directorio existente.
- `whitenoise.middleware.WhiteNoiseMiddleware` ya estaba en `MIDDLEWARE`, así que los
  estáticos de `/admin/` y DRF se siguen sirviendo sin `runserver`.

### F0-9 · `docker-compose.override.yml` de desarrollo
**No versionado** (añadido a `.gitignore`). Repone lo que la Fase 0 retira, sólo en local:
volumen `.:/usr/src/app`, `command: runserver`, `DJANGO_DEBUG=true`,
`DJANGO_VITE_DEV_MODE=true` y los puertos **atados a loopback**
(`127.0.0.1:5432`, `6379`, `9000`, `9001`, `3000`, `9090`, `8080`).

Es necesario: sin él, tras F0-6/F0-7 se pierde por completo el acceso a Grafana y Prometheus
—nginx **no tiene un bloque `server` para Grafana**, sólo declara el `upstream`— y cada
cambio de código exigiría un `docker compose build`.

Para levantar la configuración de producción tal cual, ignorando el override:

```bash
docker compose -f docker-compose.yml up -d
```

### F0-8 · Terminar sesiones y tokens vivos — **pendiente de ejecución**

Es redundante con la rotación de `SECRET_KEY` (que ya invalida todos los JWT por firma), y
se mantiene por trazabilidad de auditoría. Requiere la base de datos viva, así que queda
como **comando de despliegue**, a ejecutar tras el primer `docker compose up` con la
configuración nueva:

```bash
docker compose exec web python manage.py shell -c "
from django.contrib.sessions.models import Session
from rest_framework_simplejwt.token_blacklist.models import OutstandingToken, BlacklistedToken
print('sesiones borradas:', Session.objects.all().delete())
n=0
for t in OutstandingToken.objects.all():
    _, c = BlacklistedToken.objects.get_or_create(token=t); n += c
print('refresh tokens en lista negra:', n)"
```

---

## 7·bis. Cambios aplicados en la Fase 1 (pasos 8–20)

**Aplicada, sin commitear, verificada sólo en estático.** El orden real de ejecución no
fue el numérico del §9: se hicieron primero los pasos de menor superficie de rotura (20, 16,
10, 12, 13, 14, 17, 18, 19) y se dejaron para el final los tres de mayor riesgo (11, 15, 8),
más el 9. Lo que sigue es lo aplicado, agrupado por paso.

### Ficheros nuevos de la Fase 1
`backend/myapp/utils/request_utils.py` (paso 10), `backend/myapp/utils/cache_utils.py`
(paso 19), `backend/myapp/utils/master_key_guard.py` (paso 11),
`backend/myapp/utils/jwt_cookies.py` (paso 8), `frontend/src/config/api.ts` (paso 20),
`backend/infrastructure/nginx/ssl/` (paso 16), `backend/docker-compose.override.yml` (dev,
no versionado).

### Paso 20 — enrutado de la SPA (hecho 6)
Vite compila a `../backend/static/dist` con `manifest: 'manifest.json'` explícito;
`base.html` usa la clave de manifest `src/main.tsx`; dev server en **5174**; nuevo
`frontend/src/config/api.ts` como origen único de la URL base, del que importan los **9**
servicios (la auditoría decía 8). El puerto 8000 de `web` se cierra en `docker-compose.yml`
y se repone atado a loopback en el override.

### Paso 16 — nginx y TLS (A12)
`:80` sólo redirige a `:443`; `:443 ssl` + `http2 on`; `X-Forwarded-Proto`; `limit_req_zone`
(5 r/m en `/auth/(login|register)/`, 30 r/s en `/api/`); `limit_conn 50`;
`client_max_body_size 110m`; `server_tokens off`; consola de MinIO retirada. Certificado
autofirmado en `infrastructure/nginx/ssl/`. **`DJANGO_TLS_ENABLED=true`** en `.env` (y
`false` en el override). La CSP **no** se emite en nginx: la pone django-csp (paso 9);
nginx sólo añade `Permissions-Policy` y `Cross-Origin-Opener-Policy` (ver corrección 4).

### Paso 10 — atribución de IP (A4)
`request_utils.py` con una única `get_client_ip`, que sustituyó **10** copias (no 7) y 5
lecturas crudas de `REMOTE_ADDR`. `TRUSTED_PROXIES` decide si la cadena es creíble; la
posición la da `TRUSTED_PROXY_HOPS` (=1) contando **desde la derecha** (nginx usa
`$proxy_add_x_forwarded_for`). `get_client_ip_with_trust()` devuelve `(ip, atribuible)` y el
bloqueo de M12 sólo actúa si la IP es atribuible. Arreglo de raíz en infraestructura:
`app-network` con subred `172.28.0.0/24`, `ip_range 172.28.0.128/25` para las dinámicas y
**nginx fijado a `172.28.0.10`**; `DJANGO_TRUSTED_PROXIES=172.28.0.10/32`. El fallback
`DEFAULT_TRUSTED_PROXIES` pasa a **vacío** (fail-closed): antes reabría el agujero si alguien
quitaba el ajuste de settings.

### Paso 12 — logout y LEEWAY (A5, C6 parcial)
`SecureLogoutView._revoke_refresh_tokens`: con las cookies del paso 8, lee el refresh de la
cookie e invalida **sólo** el de este dispositivo (camino preciso); sin él, barrido completo
fail-closed. `LEEWAY` 300 → **30 s**. Además se enrutó `/api/token/refresh/`, que **no
existía** (hecho/corrección 7): sin ella `performTokenRefresh()` llevaba roto desde siempre.

### Paso 13 — temporización del login (A6)
`EmailBackend.run_dummy_hasher` ejecuta el hasher en las ramas `User.DoesNotExist`, igualando
la latencia. El coste se autoajusta: usa el primer hasher de `PASSWORD_HASHERS`, que tras el
paso 14 es Argon2.

### Paso 14 — `PASSWORD_HASHERS` (A8)
`Argon2PasswordHasher` primero, con los cuatro hashers del default de Django detrás (borrarlos
dejaría fuera de forma irreversible cualquier hash preexistente). Medido en el host: Argon2
≈ **69 ms**, PBKDF2 ≈ **375 ms**. Argon2 es más rápido en CPU; su ventaja es el **coste de
memoria: 100 MiB por hash**, que se paga en cada login, incluido el señuelo del paso 13. Con
3 workers y el pico de la subida (M3), es consumo a vigilar. **No se tunearon los parámetros
a propósito.** Esto cubre A8 sólo para las contraseñas de cuenta; las cinco derivaciones
PBKDF2 de la bóveda siguen a 100 000 iteraciones y son Fase 2.

### Paso 17 — generador acotado (M3)
`api_password_generator` con `count ∈ [1,20]` y `length ∈ [8,128]` mediante `_bounded_int`,
que devuelve **400** en vez de propagar `ValueError` como 500. Límites alineados con el
deslizante de la UI. **Trampa (corrección 12):** este endpoint no lo llama nadie vivo; el
generador real es el del cliente, con `Math.random()` (ver decisión abierta más abajo).

### Paso 18 — detección de sondeos (M12)
`SecurityLoggingMiddleware` reescrito: detección **sólo por ruta y método**, nunca por cuerpo
ni valores de parámetros (ahí viajan los secretos). Rutas de reconocimiento, extensiones
`.php/.asp/.jsp/.cgi`, `..`, byte nulo, `PUT/PATCH/TRACE/CONNECT` sobre `/api/`. Umbral **12
sondeos en 10 min → 403 durante 15 min** (antes 3 coincidencias → 1 h). User-Agent de escáner:
**sólo registra, nunca bloquea**. Un `SecurityEvent` por IP y minuto como máximo (antes, una
inserción por petición: la tabla de auditoría era el vector de DoS). Detalle de por qué esto
era peor de lo descrito: ver correcciones 9 y 10.

### Paso 19 — caché fail-closed (M6)
`IGNORE_EXCEPTIONS: False` en las dos cachés y nuevo `cache_utils.py` que **obliga a declarar
la política en cada uso**: `strict_*` levanta `CacheUnavailable` y quien llama **deniega con
503** (rate limiting de auth, bloqueo de cuenta, límite de registro, guardián de la maestra);
`lenient_*` registra ERROR y sigue (contadores de escaneo, enfriado de `SecurityEvent`,
`SessionManager`, seguimiento de sesiones). Regla: **fallar cerrado cuando la caché autoriza,
abierto y a gritos cuando sólo observa.** `SOCKET_CONNECT_TIMEOUT`/`SOCKET_TIMEOUT` a **2 s**
(sin ellos, fallar cerrado no sirve: el worker esperaría el timeout de TCP). El
`except CacheUnavailable` va **antes** del `except Exception` de cada vista, o la denegación
saldría como 500 opaco y fuera de los logs.

### Paso 11 — rate limiting real de la maestra (A3)
Dos capas. (1) `RateLimitMiddleware.classify_endpoint` reclasifica como `sensitive` **toda**
ruta que valida la maestra (`/api/unlock-password/`, `/api/unlock-all-accounts/`,
`/api/batch-delete-passwords/`, `/api/files/…`, `/api/security/`, además de las ya cubiertas);
el bloque `upload` se movió **antes** que `sensitive` para que la subida no perdiera su límite
propio. El cubo `sensitive` se subió de 50 a **70/hora** (cuenta operaciones, no fallos, así
que lo gasta también el uso normal). (2) Nuevo `master_key_guard.guard_master_password`, que
sustituye el patrón `verify_master_key` repetido en **14 vistas** por un bloqueo exponencial
**por usuario**: 4 fallos libres, luego 30·2ⁿ s hasta 1 h, contador de fallos consecutivos
que se borra al acertar. Devuelve 400 (fallo), 429 (bloqueo) o 503 (caché caída, atrapado
dentro del guardián). Las tres rutas `/passwords/{add,delete,update}/` se movieron bajo
`/api/passwords/` (3 literales en `passwordService.ts`; `base.html` y las plantillas legadas
resuelven por nombre y no cambiaron): el motivo real no era el rate limiting —que clasifica
por prefijo— sino que esas rutas quedaban fuera de las listas de auditoría, que ya nombraban
`/api/passwords/…`.

### Paso 15 — mensajes de error genéricos (M1)
**31 fugas** cerradas en 7 ficheros: `logger.exception(...)` + mensaje genérico, conservando
`error` y el código de estado (lo único que el frontend consume). Se borró la clave `details`
de los 7 sitios que la tenían. **Frontera con MinIO** (no estaba en la auditoría):
`minio_service.py` compone sus errores con el `str` de la excepción de S3, y tres vistas lo
reenviaban con `result['error']`; se cierra en la vista, que es la frontera de confianza.
Quedan 3 `str(e)` a propósito y comentados (dos que se inspeccionan y nunca se devuelven, y
el `ValueError` redactado de `_bounded_int`). De paso se cerró la **enumeración de cuentas
por código de estado** (una cuenta desactivada devolvía 403 "La cuenta está desactivada"
frente al 400 genérico): ahora delega en `handle_failed_login`, indistinguible por
construcción.

### Paso 8 — JWT en cookies HttpOnly (A1, A2)
Nuevo `CookieJWTAuthentication`: lee el access de una cookie `HttpOnly` y **sólo entonces**
exige CSRF de doble envío; si viene `Authorization: Bearer`, delega en el camino original sin
CSRF (curl y scripts siguen sirviendo). `jwt_cookies.py` centraliza la emisión
(`HttpOnly`, `Secure=_TLS`, `SameSite=Strict`, `path='/'` también para el refresh). Login y
registro emiten cookies y **ya no devuelven los tokens en el cuerpo**; logout borra las
cookies; nueva `CookieTokenRefreshView` renueva leyendo/escribiendo cookies. `authService.ts`
reescrito: **cero tokens en `localStorage`/`sessionStorage`** (sólo `user_data` para la UI),
renovación reactiva por 401. `SESSION_COOKIE_HTTPONLY=True` y ambas cookies `SameSite=Strict`.
**Bloqueador preexistente resuelto** (cerraba W015): `get_csrf_token` era `IsAuthenticated`
por defecto → 401 con base vacía; ahora `AllowAny` + `authentication_classes([])`. Se corrigió
también el desajuste de ruta del CSRF (`/auth/csrf/` → `/api/csrf/`).

### Paso 9 — Content Security Policy (A2)
`csp.middleware.CSPMiddleware` (django-csp **3.7**, config `CSP_*`). `script-src 'self'` +
**nonce por respuesta**, sin `unsafe-inline` ni `unsafe-eval`: el único inline propio (el
`<script>` de datos de `base.html`) lleva el nonce; un script inyectado no lo tiene y no corre.
`default-src 'self'`, `frame-ancestors 'none'`, `object-src 'none'`, `base-uri`/`form-action
'self'`, `connect-src 'self'`. **Residuo conocido y aceptado:** `style-src` conserva
`'unsafe-inline'` porque el frontend usa **789 atributos `style={{…}}` en 48 componentes** y
los nonces no cubren atributos de estilo; quitarlo exigiría migrar esos estilos a clases
(trabajo aparte). Un `style-src` laxo no ejecuta código: el vector de A2 (ejecución de JS) sí
queda cerrado. `img-src` permite **sólo** `https://www.google.com` para el favicon por sitio
(decisión del usuario: la petición sólo revela el dominio, hay fallback `data:` `onError`).
En `DEBUG` la CSP se relaja para el dev server de Vite (que sirve la SPA en :5174 y no está
gobernado por esta CSP); nada de eso llega a producción.

### Decisiones abiertas resueltas durante la Fase 1
- **Logout en todos los dispositivos** (era decisión abierta): resuelto por el paso 8; con la
  cookie presente, el logout invalida sólo el refresh de este dispositivo.
- **Enumeración por código de estado de cuenta desactivada**: cerrada en el paso 15.

### Residuos declarados de la Fase 1 (no ocultar al cerrar)
- **`PasswordGeneratorPage.tsx` genera con `Math.random()`**, no un PRNG criptográfico. Es el
  generador que la app usa de verdad; el endpoint del backend (`secrets.randbelow`, correcto)
  no tiene consumidor vivo. No estaba en la auditoría. **Pendiente de visto bueno** pasarlo a
  `crypto.getRandomValues`.
- **`security_views.py` conserva un `verify_master_key` crudo sin guardián** (código muerto
  bajo el 501 de F0-3): al revivirlo en Fase 2 hay que meterle `guard_master_password`.
- **`api_unlock_all_accounts` tiene el guardián puesto pero nunca se ejecuta**: sigue siendo
  `@api_view(['GET'])` con guarda `!= 'POST'` → 405 siempre (M7, Fase 3).
- **Mantenimiento:** con `ROTATE_REFRESH_TOKENS`, `token_blacklist_outstandingtoken` crece una
  fila por renovación. Hay que programar `manage.py flushexpiredtokens` (ver §11).
- **`CookieJWTAuthentication` corre dos veces** en las rutas que cubre
  `JWTAuthenticationMiddleware`: redundante, no incorrecto (ambas pasan).

---

## 7·ter. Correcciones a la auditoría descubiertas durante la Fase 1

Estos puntos contradicen lo que decían las versiones anteriores de este documento y del plan
maestro; mandan éstos.

1. **`DJANGO_VITE_ASSETS_PATH` es un ajuste muerto en django-vite 3.0.** Deciden
   `STATICFILES_DIRS`, `DJANGO_VITE_MANIFEST_PATH` y `STATIC_URL`.
2. **Vite 5+ escribe el manifest en `.vite/manifest.json`**, y `collectstatic` ignora por
   defecto todo lo que empieza por punto. De ahí el `manifest: 'manifest.json'` explícito.
3. **HSTS se aplica por host, ignorando el puerto.** Un `max-age` de un año sobre `localhost`
   forzaría HTTPS en `http://localhost:5174` y en cualquier otro proyecto de la máquina, de
   forma irreversible. De ahí los 300 s en local.
4. **`add_header` de nginx AÑADE, no reemplaza**, y dentro de un `location` anula los
   heredados del `server`. Django ya emite HSTS, `X-Frame-Options`, `nosniff` y
   `Referrer-Policy` (y ahora la CSP, vía django-csp); nginx sólo pone `Permissions-Policy` y
   `Cross-Origin-Opener-Policy`.
5. En Git Bash sobre Windows, `openssl req -subj "/C=ES/..."` necesita `MSYS_NO_PATHCONV=1`.
6. **A4 son 10 copias de `get_client_ip`, no 7**, y el modelo correcto es `TRUSTED_PROXIES`
   (credibilidad) + saltos desde la derecha (posición), no una lista blanca buscando la
   primera IP pública. **Y la lista blanca debe ser el `/32` de nginx, no los rangos
   privados**: el host entra por el gateway de la red, que también es privado.
7. **`/api/token/refresh/` no existía.** El criterio de aceptación de A5 era inejecutable; la
   ruta se añadió en la Fase 1 (y en el paso 8 pasó a `CookieTokenRefreshView`).
8. **El proyecto no tiene ni un solo test.** `backend/myapp/tests.py` son 5 líneas con un
   `print(os.urandom(32))` a nivel de módulo. Sin pytest, coverage ni factory_boy. Toda la
   verificación de la Fase 1 es estática o en aislado con dobles.
9. **M12 era peor de lo descrito**: la comparación era `pattern.lower() in path.lower()` y el
   patrón `DELETE` casaba con `/passwords/5/delete/`, `/api/files/3/delete/`,
   `/api/vaults/2/delete/` y `/api/batch-delete-passwords/`. **Borrar cuatro elementos
   bloqueaba al usuario una hora.** Además leía `request.POST` desde un middleware anterior a
   la vista, consumiendo el flujo multipart: **tercer motivo por el que la subida de ficheros
   no funcionaba**, junto con M7 (el `@api_view(['GET'])` de `upload_file_combined`).
10. **Detectar escaneo contando 404 no sirve aquí**: `urls.py` tiene un catch-all
    (`path('<path:path>', app_view)`) que devuelve **200 con la SPA** para cualquier ruta
    desconocida. Por eso la detección del paso 18 va por ruta.
11. **No existe un solo `PUT` ni `PATCH`** en el proyecto, pese a que
    `RateLimitMiddleware.classify_endpoint` los contempla.
12. **M3 tenía un consumidor equivocado**: el endpoint acotado en el paso 17 no lo llama
    nadie; el generador real es el del cliente, con `Math.random()`.

---

## 8. Arquitectura criptográfica objetivo (Fase 2)

Sustituye por completo `encryption_utils.py` y el modelo `MasterKey`.

**En el navegador — la contraseña maestra nunca sale del cliente:**

```
MK        = Argon2id(master_password, salt_usuario, m=64MiB, t=3, p=4)
AuthKey   = HKDF-SHA256(MK, info="auth")   → se envía al servidor
EncKey    = HKDF-SHA256(MK, info="enc")    → nunca sale del navegador
VaultKey  = 32 bytes aleatorios
wrapped_vault_key = AES-256-GCM(EncKey, VaultKey)   → se guarda en el servidor
```

**Por entrada:** `AES-256-GCM(VaultKey, plaintext)` con nonce aleatorio de 12 bytes y
`AAD = user_id || entry_id || crypto_version`. El servidor almacena un blob opaco y **nunca
ve texto claro**.

**En el servidor:** sólo `Argon2id(AuthKey)` (vía `PASSWORD_HASHERS` con
`Argon2PasswordHasher`), `salt_usuario` **por usuario** y `wrapped_vault_key`. Se eliminan
`decrypt_password`, `decrypt_file_data` y todo uso de `hashed_key` como clave.

Consecuencias directas:

- **C1, C2, C3 y C6 desaparecen por construcción**, no por parche.
- **M8** se resuelve: rotar la contraseña maestra es re-envolver únicamente
  `wrapped_vault_key`, sin re-cifrar la bóveda.
- El análisis de seguridad pasa al cliente: entropía local y consulta HIBP por k-anonimato
  desde el navegador. La implementación actual de k-anonimato
  (`check_password_breach_sync`) **es correcta y se reutiliza tal cual**; sólo cambia de
  lado. Con esto se reactiva lo suspendido en F0-3.
- **Ficheros:** cifrado en cliente por chunks (AES-GCM en streaming) antes de subir. La capa
  Fernet de aplicación se retira en favor del cifrado en reposo de MinIO (SSE-S3/KMS), lo
  que elimina **M2** de raíz.

---

## 9. Plan por fases

### Fase 0 — Contención inmediata ✅ APLICADA (pendiente de verificación en contenedor)

| Paso | Descripción | Hallazgos |
|------|-------------|-----------|
| F0-1 | Eliminar el volcado de claves; `hmac.compare_digest` | C4, M11 |
| F0-2 | 65 `print()` → `logger` | C4 |
| F0-3 | Suspender los dos endpoints de análisis (501) | C3, A3 |
| F0-4 | `settings.py` gobernado por entorno; TLS desacoplado | C5 |
| F0-5 | `.env` real y rotación de todos los secretos | C5, A10, M2 |
| F0-6 | Cerrar los puertos publicados | A10 |
| F0-7 | gunicorn; retirar el volumen de código | A11 |
| F0-8 | Terminar sesiones y tokens vivos | — (⏳ pendiente) |
| F0-9 | `docker-compose.override.yml` de desarrollo | — |

### Fase 1 — Endurecimiento de la superficie web (semana 1) ✅ APLICADA (sin commitear, sin verificar en contenedor)

> El detalle de lo realmente aplicado, con el orden de ejecución y las desviaciones respecto
> a este plan, está en **§7·bis**. Los pasos de abajo son el plan original; se conservan como
> referencia. Todos los 13 (8–20) están aplicados en estático. **Correcciones al plan
> descubiertas sobre el terreno: §7·ter.**

8. **Migrar JWT a cookies `HttpOnly` + `Secure` + `SameSite=Strict`**, quitando
   `localStorage`/`sessionStorage`. `SESSION_COOKIE_HTTPONLY = True`; mantener
   `CSRF_COOKIE_HTTPONLY = False` (lo exige el patrón double-submit) pero con
   `SameSite=Strict`. **(A1, A2)**
9. **Activar CSP** añadiendo `csp.middleware.CSPMiddleware` (el paquete ya está instalado):
   `default-src 'self'`, sin `unsafe-inline` ni `unsafe-eval`, `frame-ancestors 'none'`,
   `connect-src` limitado a la API. Requiere quitar los estilos inline que Vite inyecta en
   build. **(A2)**
10. **Unificar `get_client_ip`** en un único helper en `myapp/utils/` que sólo confíe en
    `X-Forwarded-For` cuando `REMOTE_ADDR` esté en una lista blanca `TRUSTED_PROXIES`;
    reemplazar las 7 copias. **(A4)**
11. **Rate limiting real sobre la contraseña maestra**: reclasificar como `sensitive` en
    `classify_endpoint` **todas** las rutas que la validan, y añadir un contador por usuario
    con bloqueo exponencial específico para fallos de clave maestra. Mover
    `/passwords/add|delete|update/` bajo `/api/passwords/` para que los middleware las
    cubran. **(A3)**
12. **Blacklist del refresh token en logout** con `RefreshToken(token).blacklist()`. Bajar
    `LEEWAY` a 30 s. **(A5, C6 parcial)**
13. **Igualar el tiempo de respuesta en `EmailBackend`** ejecutando el hasher dummy en la
    rama de usuario inexistente. **(A6)**
14. `PASSWORD_HASHERS` con `Argon2PasswordHasher` primero. **(A8)**
15. Sustituir todos los `str(e)` de respuesta por mensajes genéricos + `logger.exception`.
    **(M1)**
16. **Endurecer nginx**: TLS con la clave de `infrastructure/nginx/ssl`, redirección 80→443,
    HSTS, `limit_req_zone` por IP en `/auth/` y `/api/`, `client_max_body_size`, y dejar de
    exponer la consola de MinIO. **Al completarse, poner `DJANGO_TLS_ENABLED=true`** — no
    antes (ver F0-4). **(A12)**
17. Acotar `api_password_generator` (`count ≤ 20`, `length ≤ 128`, con `try/except
    ValueError`). **(M3)**
18. Reemplazar `SUSPICIOUS_PATTERNS` por detección basada en ruta+método y umbrales de tasa;
    nunca bloquear por IP derivada de `X-Forwarded-For`. **(M12)**
19. `IGNORE_EXCEPTIONS: False` en la caché + fallback *fail-closed* en los controles de
    seguridad. **(M6)**
20. **Arreglar el enrutado de la SPA** (hecho 6): alinear `DJANGO_VITE_ASSETS_PATH` con la
    salida real de Vite, corregir el puerto del dev server, y sustituir el
    `localhost:8000` hardcodeado de los 8 servicios del frontend por una variable de
    entorno. Sólo entonces se puede cerrar el puerto 8000 de `web`.

### Fase 2 — Rearquitectura criptográfica zero-knowledge (semanas 2-4)

21. **Nuevos modelos** (migración aditiva, sin tocar los antiguos):
    `UserCrypto(user, kdf_salt, kdf_params, auth_key_hash, wrapped_vault_key, crypto_version)`;
    añadir `crypto_version` y `ciphertext` (blob AEAD) a `PasswordEntry` y `EncryptedFile`.
22. **Módulo cripto de cliente** (`frontend/src/services/crypto.ts`) con WebCrypto +
    `argon2-browser`: derivación, envoltura/desenvoltura de `VaultKey`, cifrado/descifrado
    AES-GCM por entrada y cifrado por chunks para ficheros. La `VaultKey` vive **sólo en
    memoria**, nunca en `localStorage`, con auto-bloqueo por inactividad.
23. **Reescribir los endpoints** para que operen sobre blobs opacos (`password_views.py`,
    `file_views.py`, `masterkey_views.py`). Borrar `decrypt_password` y `decrypt_file_data`
    del servidor.
24. **Contraseñas de bóveda privada**: derivar una `VaultSubKey` en el cliente y envolverla
    igual que la principal. Eliminar el flag `vault_already_unlocked` y filtrar el contenido
    de bóvedas privadas hasta que el cliente demuestre posesión de la subclave. **(A9)**
25. **Implementar la rotación de la clave maestra** re-envolviendo `wrapped_vault_key` en el
    cliente. **(M8)**
26. **Migración de datos**: los registros `crypto_version=1` se marcan como *legacy* y de
    sólo lectura; asistente de exportación/reimportación en el frontend; purga tras un plazo
    anunciado. **Aviso explícito a los usuarios de que su bóveda anterior debe considerarse
    comprometida.**
27. Reimplementar el análisis de seguridad en cliente y **reactivar lo suspendido en F0-3**.
28. Cifrado en reposo de MinIO (SSE) y retirada de la capa Fernet de aplicación. **(M2)**

### Fase 3 — Defensa en profundidad y cadena de suministro (mes 2)

29. **MFA (TOTP)** en el login y como segundo factor obligatorio al desbloquear la bóveda
    desde un dispositivo nuevo — es la única mitigación real del phishing, y el registro de
    dispositivos de confianza ya está implementado a medias. **(M9)**
30. **Verificación de email en el registro** y **notificación por correo de login desde
    dispositivo o IP nuevos** (la detección ya existe en
    `SessionManager.analyze_session_security`; falta el canal de aviso).
31. **Actualizar dependencias** (`cryptography`, `Django` a la 5.1.x parcheada, `requests`,
    `urllib3`), fijar con hashes (`uv pip compile --generate-hashes`) y añadir `pip-audit` +
    `npm audit` a CI. **(M5)**
32. Corregir el código muerto/roto: `api_unlock_all_accounts`, `upload_file_combined`
    **(M7)** y `getattr("settings", …)` **(M10)**.
33. Subida de ficheros por streaming en lugar de lectura completa en memoria, y coherencia
    entre el límite de 100 MB y `DATA_UPLOAD_MAX_MEMORY_SIZE`. **(M3)**
34. `Content-Type` de descarga fijado a `application/octet-stream` salvo lista blanca.
    **(M4)**
35. Alertas en Grafana sobre `SecurityEvent`: picos de fallos de clave maestra, cambios de
    IP en sesión, bloqueos de cuenta.

---

## 10. Verificación

### Ya verificado (estático, en el host)

**Fase 0**
- `py_compile` correcto en los 8 ficheros Python modificados.
- **0** ocurrencias de `print(` y de `traceback.print_exc` en `myapp/views/`, `models.py`,
  `encryption_utils.py`, `middleware.py` y `demo/`.
- `settings.py` **lanza `KeyError: 'DJANGO_SECRET_KEY'`** si la variable no está definida.
- Cargando `backend/.env` igual que hará Compose: `DEBUG=False`, `SECURE_SSL_REDIRECT`
  ausente, `SESSION_COOKIE_SECURE=False`, `ALLOWED_HOSTS=['localhost','127.0.0.1','web']`,
  `SECRET_KEY` de 64 caracteres y sin el prefijo `django-insecure`, contraseña de Postgres
  distinta de `password`, y las dos cachés Redis en **bases distintas** (`/1` y `/2`), ambas
  con contraseña.
- `docker-compose.yml` y `docker-compose.override.yml` parsean como YAML válido; sólo `web`
  y `nginx` declaran `ports`; el comando de gunicorn queda en **una sola línea**.
- `git check-ignore` confirma que `backend/.env` y `backend/docker-compose.override.yml`
  están ignorados, y que `backend/.env.example` **no** lo está.

**Fase 1** (toda la verificación es estática o en aislado; ver el aviso de la cabecera y la
corrección 8: el proyecto no tiene tests)
- `tsc --noEmit` limpio; el build de Vite deja `manifest.json` en `backend/static/dist` con
  la clave `src/main.tsx`; `nginx -t` correcto; `py_compile` en todos los ficheros tocados.
- `docker compose -f docker-compose.yml config` y `docker compose config` resuelven el `ipam`
  y el `ipv4_address` (el override no toca `networks`).
- Una sola `def get_client_ip` en `myapp/`; cero `cache.get/set/delete` crudos fuera de
  `cache_utils.py` salvo dos en tareas de limpieza ya envueltas en `try/except`.
- Cero `str(e)` que lleguen al cliente y cero `'details'` en `myapp/views/` (quedan 3 `str(e)`
  a propósito, comentados); cero literales `/passwords/` en `frontend/src`; cero referencias a
  `/auth/csrf/`.
- Pruebas en aislado ejecutando el **código real** con dobles de Django (viven en el
  scratchpad, no en el repo): 14 de atribución de IP (paso 10), 28 de detección (paso 18), 18
  de la caché fail-closed (paso 19), 14 del `_bounded_int` (paso 17), 20 del guardián de la
  maestra (paso 11) y 8 de la decisión de `CookieJWTAuthentication` (paso 8). Todas correctas.

### Pendiente — requiere `docker compose up` (Fase 0 **y** Fase 1)

`manage.py check` no se puede ejecutar fuera del contenedor (hecho 3). **Nada de lo siguiente
se ha ejecutado todavía**, ni de la Fase 0 ni de la Fase 1: la pila no se ha levantado.

> **La red cambió de direccionamiento (paso 10).** Antes de levantar hay que
> `docker compose -f docker-compose.yml down` (**SIN `-v`**), o el `up` falla con "network
> needs to be recreated". Y ojo con el `-f`: **sin él, Compose aplica el override** (dev:
> `runserver`, `DEBUG=true`, `TLS=false`) y estarías probando otra cosa.

```bash
cd backend
docker compose -f docker-compose.yml down            # SIN -v (la red se recrea)
docker compose -f docker-compose.yml up -d --build

docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' backend-proxy
#   → 172.28.0.10 (nginx fijo, fuera del rango dinámico)

docker compose -f docker-compose.yml config | grep -Ei "password|secret|key"   # sólo refs

docker compose -f docker-compose.yml exec web python manage.py check --deploy
#   Fase 0: deben desaparecer W009 y el aviso de DEBUG.
#   Fase 1: con DJANGO_TLS_ENABLED=true deben desaparecer W004/W008/W012/W016 y
#   django_vite.W001. W015 (SECRET_KEY en HS256 sobre los JWT) se cierra con el paso 8.

curl -kI https://localhost/          # 200 + HSTS, X-Frame-Options, Permissions-Policy, CSP
curl -I  http://localhost/           # 301 -> https
docker compose -f docker-compose.yml logs web | grep -E "Starting gunicorn|Booting worker" # 1+3
docker compose -f docker-compose.yml exec redis redis-cli ping   # → NOAUTH Authentication required
```

**Prueba funcional obligatoria** (paso 20 hizo utilizable la ruta servida por Django). Con
`ENCRYPTION_KEY` fija y 3 workers, **descargar el mismo fichero 6 veces debe dar siempre el
mismo `sha256`** (M2 cerrado hacia delante, hecho 2) — el arreglo de M7 ya lo permite.

### Criterios de aceptación de la Fase 1 — PENDIENTES de contenedor

- `curl -kI https://localhost/` → cabeceras `Content-Security-Policy` (con `script-src` que
  incluye un `nonce-…` y **sin** `unsafe-inline` en `script-src`),
  `Strict-Transport-Security` y `X-Frame-Options`.
- Enviar ≥5 contraseñas maestras erróneas a **cualquiera** de las rutas que la validan
  (`/api/unlock-password/1/`, `/api/passwords/<id>/delete/`, `/api/files/<id>/download/`…) →
  la 5ª debe cortar con **429**, y con la correcta durante el bloqueo debe seguir dando 429.
- Repetir **variando `X-Forwarded-For`** en cada petición → debe seguir cortando (el guardián
  es por usuario; el bloqueo por IP de M12 sólo actúa con IP atribuible).
- Login → **en DevTools, `access_token` y `refresh_token` como cookies `HttpOnly`**;
  `document.cookie` no las muestra (sí `csrftoken`).
- POST a `/api/passwords/add/` **sin** cabecera `X-CSRFToken` → **403**; con ella → 200.
- Login en dos navegadores → logout en uno → el otro sigue dentro (logout preciso, paso 8).
- Login → borrar sólo la cookie `access_token` → una acción cualquiera debe renovar sola vía
  `/api/token/refresh/` y reintentar.
- Medir 100 logins con email existente frente a inexistente → diferencia dentro del ruido
  (A6); y una cuenta desactivada debe devolver **400 genérico**, no 403.
- Provocar un 500 real (p. ej. parar `minio` y pedir una descarga) → el cliente recibe un
  mensaje genérico y la traza queda **sólo** en `infrastructure/logs/django/` (M1).

### Criterios de aceptación de fases posteriores

**Fase 2**
- Volcar la base con `pg_dump` y comprobar que **ninguna** columna permite recuperar texto
  claro sin la contraseña maestra del usuario.
- Test de integridad: alterar un byte de `ciphertext` en la base → el descifrado en cliente
  debe **fallar explícitamente** (hoy devuelve basura en silencio).
- Confirmar por inspección de red que la contraseña maestra **nunca** aparece en ninguna
  petición.
- Cambiar la contraseña maestra y verificar que la bóveda sigue accesible sin re-cifrado
  masivo.
- `GET /api/vaults/<id>/passwords/` sobre una bóveda privada bloqueada → debe denegar.

**Fase 3**
- `pip-audit` y `npm audit --production` sin vulnerabilidades altas o críticas.
- Login desde IP o dispositivo nuevo → llega el aviso por correo y se exige TOTP.

---

## 11. Despliegue y rollback

### Primer arranque con la configuración nueva

> **Con la Fase 1, la red cambió de direccionamiento (paso 10).** Sobre una pila ya creada
> hay que `docker compose -f docker-compose.yml down` (**SIN `-v`**) antes del `up`, o falla
> con "network needs to be recreated". Y compilar el frontend antes del build:
> `cd frontend && npm run build`.

```bash
cd frontend && npm run build && cd ../backend
cp .env.example .env      # y rellenar TODOS los valores (o usar el .env ya generado)

# Copia de seguridad antes de tocar nada
docker compose -f docker-compose.yml exec db pg_dump -U myuser mydb | gzip > ~/backup-pre-fase0.sql.gz

docker compose -f docker-compose.yml down          # SIN -v (la red se recrea)
docker compose -f docker-compose.yml up -d --build
```

**Rotaciones que Compose no puede hacer por sí solo** (hecho 10) — ejecutar **una vez**,
sobre los volúmenes ya existentes:

```bash
# Postgres: POSTGRES_PASSWORD sólo se aplica en el initdb
docker compose exec db psql -U myuser -d mydb \
  -c "ALTER USER myuser WITH PASSWORD '<la de backend/.env>';"

# Grafana: idéntico comportamiento
docker compose exec grafana grafana-cli admin reset-admin-password '<la de backend/.env>'
```

MinIO **no** necesita nada: relee sus credenciales root en cada arranque.

Después, ejecutar el comando de **F0-8** (§7) para purgar sesiones y tokens vivos.

**Mantenimiento programado (Fase 1).** Con `ROTATE_REFRESH_TOKENS` activo, cada renovación
añade una fila a `token_blacklist_outstandingtoken`. Hay que programar la purga (cron del
host, o un contenedor de tarea):

```bash
docker compose -f docker-compose.yml exec web python manage.py flushexpiredtokens
```

### Rollback

1. **Punto de retorno creado:** etiqueta `pre-fase0` sobre el commit `add989a`. Antes de
   reconstruir la imagen conviene además
   `docker image tag backend-web:latest backend-web:pre-fase0`.
2. **Copia de seguridad de la base** antes de la rotación de credenciales (comando arriba).
3. **Estado de los commits.** La **Fase 0** es el commit `2d360a5 "Mejoras seguridad 1"` (un
   único commit, revert todo-o-nada). La **Fase 1 está aplicada pero SIN commitear**: los
   commits los gestiona el usuario. Hasta que se commitee, el rollback de la Fase 1 es
   `git stash`/`git checkout -- .` sobre los ficheros tocados (lista en §7·bis), no
   `git revert`. Al levantar tras el re-direccionamiento de red, `docker compose down` sin
   `-v` (no perder volúmenes).
4. **Vuelta atrás rápida sin tocar git** (cubre el 80 % de los fallos, ~30 s): en
   `backend/.env`, poner `DJANGO_DEBUG=true`, `DJANGO_TLS_ENABLED=false` y ampliar
   `CORS_ALLOWED_ORIGINS`; y usar el `docker-compose.override.yml`, que ya trae
   `command: runserver` y el volumen de código.
5. **Irreversible y asumido:** la rotación de `SECRET_KEY` invalida todos los JWT, así que
   **todos los usuarios deben volver a iniciar sesión**. Es el efecto deseado.

---

## 12. Recomendación final

La Fase 0 cerró las vías por las que el sistema se desangraba hacia fuera: logs, credenciales
públicas, puertos abiertos y un servidor de desarrollo en producción. La **Fase 1** ha
endurecido la superficie web alrededor de ese núcleo: TLS y cabeceras, CSP, JWT en cookies
`HttpOnly`, rate limiting real de la maestra, atribución de IP fiable, fail-closed de la
caché y mensajes de error genéricos. Es endurecimiento sólido —y **aún sin verificar en
contenedor**— pero sigue siendo perímetro. Ninguna de esas mejoras toca el problema.

**El problema es C1**, y mientras siga presente cualquier persona con acceso de lectura a la
base de datos —hoy, mañana, o en una copia de seguridad de hace seis meses— tiene todas las
contraseñas de todos los usuarios. Ese acceso puede ser legítimo (un administrador, una
restauración de backup) o no, y el diseño actual no distingue entre ambos casos.

Por eso, **no se debe abrir el servicio a usuarios reales antes de completar la Fase 2**. Si
hubiera que ponerlo en marcha antes, la única postura honesta es advertir de forma explícita
a cada usuario, en el registro, de que el operador del servicio puede leer su bóveda —que es
exactamente lo contrario de lo que un gestor de contraseñas promete.
