# Plan de pruebas — Gestor de Contraseñas

**Proyecto:** Django 5.1 + DRF + JWT / React-Vite / PostgreSQL / Redis / MinIO / Docker
**Rama:** `tokens`
**Documento hermano:** [AUDITORIA-SEGURIDAD.md](AUDITORIA-SEGURIDAD.md)
**Estado del código de referencia:** commits `2d360a5`, `73bd0df`, `98b8d95`, `51958d1`, `26b4c97`
(Fases 0, 1 y 2 completas) más cambios sin commitear en el árbol de trabajo.

> Este plan documenta el **delta contra el código real** (verificado sobre los ficheros y
> `git log`), **no** contra `AUDITORIA-SEGURIDAD.md`, que va por detrás del código. Cuando ambos
> difieren, manda el código y se anota la divergencia (ver §1.1).

---

## 1. Propósito

Cuando se diseñó la auditoría, `AUDITORIA-SEGURIDAD.md` describía 30 hallazgos con la Fase 0
commiteada y las Fases 1-3 pendientes. **Ese ya no es el estado del repo.** Sobre la rama
`tokens` se han acumulado cinco cambios grandes que cierran las Fases 1 y 2 (rearquitectura
**zero-knowledge**): `MasterKey` está purgado (migración `0025`) y sustituido por `UserCrypto`;
existe un núcleo cripto de cliente ([frontend/src/services/crypto.ts](frontend/src/services/crypto.ts));
hay cookies JWT `HttpOnly`, CSP activa, `Argon2PasswordHasher`, `LEEWAY: 30`, blacklist de
refresh, `IGNORE_EXCEPTIONS: False`, `client_id` UUID único (anti-swap) y subclaves de bóveda
privada.

**Esto invierte el propósito de la suite.** Ya no se trata de escribir tests que *deben fallar
hoy* para marcar una meta sin empezar. Se trata de **blindar una rearquitectura enorme que
apenas se ha ejercido**:

- La pila **se levantó una vez** (25 jul, `stack_dev`, BD fresca) y afloraron **dos bugs de
  integración que el estático no vio**: `crypto.ts` pasaba siempre `additionalData` a AES-GCM y
  el navegador lanzaba con `undefined` (el WebCrypto de Node lo tolera → `tsc`/`py_compile` no
  lo detectaban), y **faltaba el flujo de desbloqueo** entero (la `VaultKey` sólo vive en
  memoria; tras recargar, la bóveda quedaba bloqueada). Ambos corregidos.
- **Nunca se ha levantado `stack_prod`** (gunicorn ×3, TLS, nginx). Siguen sin ejecutarse: M2
  (3 workers → mismo `sha256`), cabeceras/TLS de borde, conteo de workers y la cadena
  Vite→collectstatic→whitenoise→nginx (T1-d).
- `crypto.ts` sólo ha corrido **en el navegador**. No hay ninguna ejecución **repetible** de la
  cripto del cliente — que es justo lo que aporta L3-vitest.

La lección del bug de `additionalData` condiciona el diseño: (1) el estático no basta; (2)
**Node/jsdom es más permisivo que el navegador**, así que vitest tiene un punto ciego declarado
(Z14). La suite es, sobre todo, la **prueba de aceptación y la red de regresión de
zero-knowledge**: la definición ejecutable de "la Fase 2 realmente funciona".

### 1.1 Delta contra el diseño de la auditoría (divergencias verificadas)

| Hallazgo | Lo que decía el diseño / la auditoría | Estado real en el código (jul 2026) |
|---|---|---|
| **N2** (`Math.random()` en el generador) | Abierto; `PasswordGeneratorPage.tsx` usa `Math.random()`; xfail estático hasta el visto bueno del usuario | **Cerrado en el árbol de trabajo.** El commit `26b4c97` añade [frontend/src/services/passwordGenerator.ts](frontend/src/services/passwordGenerator.ts) (CSPRNG: `crypto.getRandomValues` con rejection sampling y Fisher-Yates insesgado); los **tres** consumidores (`PasswordGeneratorPage.tsx`, `AddPasswordModal.tsx`, `EditPasswordModal.tsx`) lo importan. El único `Math.random` que queda es un comentario que describe lo que se retiró. → El test N2 **deja de ser xfail**: pasa de ❌ a ⚠️ ("debería pasar, nunca ejecutado"), y se convierte en test de regresión de que el CSPRNG no se revierte. |
| **M1** (straggler `str(e)`) | Un `str(e)` en [general_views.py:147](backend/myapp/views/general_views.py#L147) | Reverificar en la tanda de L0 de código fuente. Si sigue, xfail estricto; si ya no está, XPASS avisa. |
| **N1**, **T3** | Nuevos, ya resueltos (`CookieTokenRefreshView`, `/api/csrf/` `AllowAny`) | Confirmado en código. Tests ⚠️. |

**Abiertos que quedan (Fase 3):** **M5** (deps sin actualizar) y **M9** (MFA/verificación de
email). Son los únicos xfail estrictos de peso una vez cerrado N2.

De 30 hallazgos, **27 están cerrados en el código**; con N2 cerrado en el árbol de trabajo, el
inventario de deuda real es M5, M9 y (a confirmar) el straggler de M1. Por eso la inmensa
mayoría de los tests **deben pasar hoy** —aunque nunca se hayan ejecutado— y sólo un puñado son
xfail estrictos.

---

## 2. Escala de niveles

| Nivel | Qué es | Dónde corre | Necesita |
|---|---|---|---|
| **L0** | Repo y configuración estática: ficheros como texto, YAML o AST. **Nunca importa Django.** | host | `pytest` |
| **L1** | Unitario Django: ORM, `settings`, middleware con `RequestFactory`, `UserCrypto`. | **dentro del contenedor `web`** | pila levantada |
| **L2** | Integración por HTTP real contra la pila. | host (cliente HTTP) | pila levantada |
| **L3** | Frontend: `crypto.ts` y `passwordGenerator.ts` con **vitest**. | host (Node) | `npm i` dev |
| **L4** | Manual, con guion paso a paso. Registrado en pytest como `skip`/`manual` para que se liste. | humano | — |

**Etiqueta de pila** (`stack_prod` / `stack_dev`), obligatoria en L1 y L2:

- `stack_prod` → `docker compose -f docker-compose.yml …` (gunicorn ×3, `DEBUG=false`,
  `TLS=true`, sin volumen de código, sólo nginx publica 80/443).
- `stack_dev` → `docker compose up` a secas (aplica el override: runserver, `DEBUG=true`,
  `TLS=false`, puertos en loopback incluido `web:8000`).

**Por qué importa** (trampa 4): nginx corta a **5r/m** en `/auth/(login|register)/` antes de que
la petición llegue a `RateLimitMiddleware`. Un test de rate limiting de aplicación contra el 443
mide **nginx**, no la app → falso verde. Por eso A3-b ataca `web:8000` (`stack_dev`) y A12-c
ataca `:443` (`stack_prod`). Son tests distintos; el documento lo dice en cada entrada.

### 2.1 Por qué L0 no puede importar Django

1. [settings.py:39](backend/demo/settings.py#L39) es `os.environ["DJANGO_SECRET_KEY"]` sin
   fallback → `KeyError` en el host.
2. `minio_service.py` instancia el servicio a nivel de módulo → importar `myapp.views` bloquea
   ~20 s resolviendo `minio` (trampa 2).

Los L0 leen ficheros como **texto/YAML/AST** (`ast.parse` no ejecuta el módulo); los L1 viven
forzosamente dentro del contenedor.

---

## 3. Mecanismo para los pocos tests que deben fallar hoy

`@pytest.mark.xfail(strict=True, reason="<ID> — cierra en Fase N")` + marcador de fase
(`@pytest.mark.fase3`). Con Fases 0-2 cerradas y N2 cerrado en el árbol, esto aplica a **muy
pocos** tests: M5, M9 y (si sobrevive) el straggler de M1.

- Hoy la suite es **verde**: esos tests salen `XFAIL` (`x`), no fallo.
- `strict=True` → un **XPASS es fallo rojo** (reforzado con `xfail_strict = true` en `pytest.ini`):
  el día que la Fase 3 cierre M5, la suite grita "quita el xfail de M5". Un test que falla a
  propósito y no avisa cuando deja de fallar se borra; éste no.
- `pytest -m fase3 --runxfail` los ejecuta en serio y enseña el fallo real.
- `pytest -ra` lista los motivos de xfail (por eso el `reason` empieza por el ID): la salida del
  runner es, por sí sola, el inventario de deuda restante.

**Estados usados en las tablas:**

- ✅ **pasa y verificado** (test ejecutado en verde).
- ⚠️ **debería pasar, nunca ejecutado.** Es el estado de casi todo el plan. No es xfail (no
  esperamos que falle), pero tampoco está verificado. **La primera ejecución en contenedor es la
  que convierte ⚠️ en ✅ o descubre un fallo real de la rearquitectura — y ése es el entregable
  de valor**, no el andamiaje.
- ❌ **debe fallar hoy** (xfail estricto).
- ⏭️ **no aplicable** (se salta según la pila).

---

## 4. Inventario de pruebas

### 4.1 Zero-knowledge — la columna vertebral nueva (Fase 2)

Estos tests **no existían en el diseño original** porque el esquema que prueban tampoco. Son los
criterios de aceptación de la §10 de la auditoría, ahora ejecutables.

| ID | Qué demuestra | Nivel / pila | Hoy |
|---|---|---|---|
| **Z1** | ⭐ **`pg_dump` sin texto claro.** Volcar la BD y afirmar que ninguna columna de `PasswordEntry`/`EncryptedFile`/`UserCrypto` permite recuperar texto claro sin la maestra: sólo hay `ciphertext` opaco, `wrapped_vault_key`, `auth_key_hash` (Argon2) y `kdf_salt`. Criterio §10 de C1. | L2 `stack_prod` | ⚠️ |
| **Z2** | ⭐ **AEAD detecta manipulación.** En `crypto.ts`: voltear un byte del `ciphertext` → `decrypt` **lanza**, no devuelve basura. Es C6 y el criterio §10 de integridad. Sólo comprobable en L3: el servidor es zero-knowledge y no descifra. | L3 vitest | ⚠️ |
| **Z3** | **Round-trip de derivación.** `MK = Argon2id(pwd, salt, KDF_PARAMS)` es determinista y reproduce el mismo `AuthKey`/`EncKey`; `wrap(EncKey, VaultKey)` → `unwrap` devuelve la `VaultKey` original. | L3 vitest | ⚠️ |
| **Z4** | **Vectores KDF fijos.** Un `(password, salt)` conocido produce un `MK` conocido con `KDF_PARAMS` (m=65536, t=3, p=4, v=19). Ancla el KDF: si alguien cambia un parámetro, las bóvedas existentes dejarían de abrir y el test lo caza antes del deploy. **Vector compartido con el helper Python del `conftest` (trampa 14).** | L3 vitest | ⚠️ |
| **Z5** | **`UserCrypto` no reconstruye la MK.** `verify_auth_key` usa `check_password` (Argon2, tiempo constante) y el modelo no guarda ni la maestra ni la `EncKey`: sólo `auth_key_hash` y `wrapped_vault_key`. Sustituye al viejo C1-b. | L1 | ⚠️ |
| **Z6** | **Sal por usuario.** Dos `UserCrypto` nuevos tienen `kdf_salt` distintos. Sustituye a C2-b. | L1 | ⚠️ |
| **Z7** | **La maestra nunca viaja.** En el flujo login/setup/verify por HTTP, ningún cuerpo de petición contiene la contraseña maestra en claro: sólo `auth_key` derivada. Criterio §10. | L2 `stack_dev` | ⚠️ |
| **Z8** | ⭐ **Anti-swap `client_id`.** `PasswordEntry.client_id` es `unique`: guardar dos filas con el mismo `client_id` (atacante con escritura en BD copiando ciphertext+client_id de otra fila) viola la restricción. | L1 | ⚠️ |
| **Z9** | **AAD atada a la identidad.** En `crypto.ts`, descifrar un `ciphertext` con `entry_id`/`user_id` distinto del usado al cifrar (AAD = `user_id\|entry_id\|crypto_version`) **falla**: un blob reubicado no se abre. | L3 vitest | ⚠️ |
| **Z10** | **Rotación sin re-cifrado (M8).** `POST /api/master-key/change/` re-envuelve `wrapped_vault_key` y la bóveda sigue accesible sin tocar los `ciphertext` de las entradas. Criterio §10. | L2 `stack_dev` | ⚠️ |
| **Z11** | **Bóveda privada deniega (A9).** `GET /api/vaults/<id>/passwords/` sobre privada bloqueada → deniega; un `vault_already_unlocked: true` del cliente **no** salta nada (el flag se eliminó; ahora hay `sub_auth_key_hash`). | L2 `stack_dev` | ⚠️ |
| **Z12** | **Subclave de bóveda espeja a UserCrypto.** `Vault.verify_sub_auth_key` devuelve `False` si la bóveda no es privada o no tiene `sub_auth_key_hash`, y `True` sólo con la SubAuthKey correcta. | L1 | ⚠️ |
| **Z13** | **Cifrado de ficheros por chunks.** En `crypto.ts`, un fichero > `FILE_CHUNK_SIZE` (1 MiB) se cifra y descifra por chunks con round-trip exacto byte a byte. | L3 vitest | ⚠️ |
| **Z14** | ⭐ **Regresión del bug real: `wrap`/`unwrap` SIN AAD.** `wrapVaultKey`/`unwrapVaultKey` no pasan `additionalData` a AES-GCM (bug del 25 jul: con `undefined` el navegador lanzaba, Node no). **Punto ciego declarado:** vitest corre en Node, que lo tolera → este test **no** reproduce el fallo del navegador; se marca como regresión de la *forma del código* (afirma que `AesGcmParams` no lleva la clave cuando no hay AAD) y su verificación real de navegador es **L4** (o Playwright si se monta). | L3 + L4 | ⚠️ |
| **Z15** | **Regresión del flujo de desbloqueo.** Tras login/recarga la `VaultKey` se pierde (sólo vive en `cryptoSession`); `verifyMasterKey` la reconstruye y `/accounts/` descifra. Faltaba entero hasta el 25 jul. La parte de sesión (`cryptoSession.unlock`/`lock`, auto-bloqueo 15 min) es L3; el flujo E2E navegador es **L4**. | L3 + L4 | ⚠️ |

### 4.2 Críticos (reencuadrados: casi todos cerrados)

| ID | Qué demuestra | Nivel / pila | Hoy |
|---|---|---|---|
| **C1** | Ver **Z1** (pg_dump) + **Z5** (`UserCrypto`). `MasterKey` **no existe** (migración 0025); test: `myapp.models` no exporta `MasterKey`. | L1 + L2 | ⚠️ |
| **C2** | Ninguna migración conserva sal viva: `0025` borró `passwordentry.salt` y `masterkey.salt`. Test: el esquema actual no tiene esas columnas. | L1 | ⚠️ |
| **C3** | `/api/security/analysis/` y `/check-breach/` **ya no existen** (retirados, no 501). Quedan `/api/security/hibp-range/<prefix>/` (proxy k-anonimato) y `/recommendations/`. Test: viejas rutas → 404; nuevas → responden autenticadas. | L2 `stack_dev` | ⚠️ |
| **C4-a** | 0 `print(` / `traceback.print_exc` en `myapp/views/`, `models.py`, `encryption_utils.py`, `middleware.py`, `demo/`. | L0 | ⚠️ |
| **C4-b** | `docker compose logs web` sin `Derived Key` ni `Generated new system encryption key`. | L2 `stack_prod` | ⚠️ |
| **C5-a** | `settings.py` sin `django-insecure`; `SECRET_KEY` de `os.environ`; `DEBUG` de `_env_bool`. | L0 | 🧪 |
| **C5-b** | `manage.py check --deploy` sin **W009** ni aviso de DEBUG. Con TLS de nginx, **tampoco** W004/W008/W012/W016. | L2 `stack_prod` | ⚠️ |
| **C6** | Ver **Z2** (AEAD tamper) + `LEEWAY <= 30` en settings. | L3 + L1 | ⚠️ |

### 4.3 Altos (reencuadrados)

| ID | Qué demuestra | Nivel / pila | Hoy |
|---|---|---|---|
| **A1-a** | `authService.ts` no guarda tokens en `localStorage`/`sessionStorage`. | L0 | ⚠️ |
| **A1-b** | La respuesta de login trae `Set-Cookie` `HttpOnly`+`SameSite`, y el cuerpo JSON **no** contiene `access`/`refresh`. | L2 `stack_prod` | ⚠️ |
| **A2-a** | `csp.middleware.CSPMiddleware` en `MIDDLEWARE`; `CSP_DEFAULT_SRC = ("'self'",)`, `CSP_FRAME_ANCESTORS = ("'none'",)`, sin `unsafe-eval` en producción. | L0 | 🧪 |
| **A2-b** | `SESSION_COOKIE_HTTPONLY = True`; `CSRF_COOKIE_HTTPONLY = False` a propósito (double-submit). | L0 | 🧪 |
| **A2-c** | `GET https://localhost/` devuelve `Content-Security-Policy` con `nonce` en `script-src` y sin `unsafe-inline`/`unsafe-eval`. | L2 `stack_prod` | ⚠️ |
| **A2-d** | `base.html` usa `nonce="{{ request.csp_nonce }}"` en el `<script>` de `window.DjangoData`. | L0 | ⚠️ |
| **A3-a** | `classify_endpoint` devuelve `sensitive` para las rutas que validan la maestra; `master_key_guard` aplica bloqueo exponencial por usuario (4 gratis, luego 30·2ⁿ s). | L1 | ⚠️ |
| **A3-b** | 20 maestras erróneas al endpoint que las valida → corta (429/503). ⚠️ contra `web:8000`, no nginx. | L2 `stack_dev` | ⚠️ |
| **A4-a** | Una sola definición de `get_client_ip` en `utils/request_utils.py`; los consumidores la importan. | L0 | ⚠️ |
| **A4-b** | Con `REMOTE_ADDR` público se ignora `X-Forwarded-For`; con proxy de confianza se toma la posición `TRUSTED_PROXY_HOPS` desde la derecha. | L1 | ⚠️ |
| **A4-c** | El ataque de A3-b **variando `X-Forwarded-For`** sigue cortando. | L2 `stack_dev` | ⚠️ |
| **A5** | Tras logout, el `jti` del refresh aparece en `BlacklistedToken`; reusar el refresh en `CookieTokenRefreshView` → 401. | L1 + L2 `stack_dev` | ⚠️ |
| **A6-a** | `EmailBackend` ejecuta el hasher también con usuario inexistente. Determinista (se espía el hasher). Con Argon2 primero (paso 14), verificar que el señuelo también es Argon2. | L1 | ⚠️ |
| **A6-b** | 100 logins existente vs. inexistente dentro del ruido. **L4 manual** (flaky como automático). | L4 | ❌xfail-manual |
| **A7** | `GET /api/accounts/` devuelve `ciphertext`+`client_id`, **no** columnas v1. | L2 `stack_dev` | ⚠️ |
| **A8-a** | `PASSWORD_HASHERS[0]` es `Argon2PasswordHasher`. | L1 | ⚠️ |
| **A8-b** | KDF del cliente Argon2id con `KDF_PARAMS` (ver Z4); en servidor no queda ningún `iterations=100000` residual. | L0 + L3 | ⚠️ |
| **A9** | Ver **Z11** + **Z12**. | L1 + L2 | ⚠️ |
| **A10-a** | `docker-compose.yml`: sólo `nginx` con `ports`; ningún literal de credencial; `redis --requirepass`; `${VAR:?…}` sin defaults inseguros. | L0 | ⚠️ |
| **A10-b** | 5432/6379/9000/9001/3000/9090/8080 cerrados. Sólo `stack_prod`; con override están abiertos a propósito → el test se **salta**. | L2 `stack_prod` | ⚠️ |
| **A11-a** | Compose base: gunicorn `--workers 3`, sin `.:/usr/src/app`, sin `DEBUG=1`. | L0 | ⚠️ |
| **A11-b** | `logs web`: 1 `Starting gunicorn` + 3 `Booting worker`. | L2 `stack_prod` | ⚠️ |
| **A12-a** | `nginx.conf`: `listen 443 ssl`, `:80` → 301, `limit_req_zone` 5r/m + 30r/s, `limit_conn 50`, `client_max_body_size 110m`, `server_tokens off`, sin bloques MinIO. | L0 | ⚠️ |
| **A12-b** | `http://localhost/` → 301 a `https://`. Autofirmado → `verify=False` con aviso silenciado (trampa 5). | L2 `stack_prod` | ⚠️ |
| **A12-c** | 10 peticiones a `/auth/login/` por el 443 → 429. Éste **sí** mide nginx (contraparte de A3-b). | L2 `stack_prod` | ⚠️ |

### 4.4 Medios (reencuadrados)

| ID | Qué demuestra | Nivel / pila | Hoy |
|---|---|---|---|
| **M1** | 0 `str(e)` en cuerpos de respuesta de `myapp/views/` — **salvo el straggler** en [general_views.py:147](backend/myapp/views/general_views.py#L147). El test afirma "≤ 1 y sólo en `general_views`" con xfail hasta que se cierre; cuando llegue a 0, XPASS avisa. | L0 | ❌ (a confirmar) |
| **M2** | ⭐ 6 descargas → mismo `sha256`. Con zero-knowledge el servidor guarda blob opaco; prueba que MinIO devuelve bytes idénticos y `ENCRYPTION_KEY` de sistema es estable entre 3 workers. Punto de partida: `smoke.py` adaptado. | L2 `stack_prod` | ⚠️ |
| **M3-a** | `/api/password-generator/?count=100000&length=100000` → **400** (`_bounded_int` acota); `count=abc` → 400, no 500. | L2 `stack_dev` | ⚠️ |
| **M3-b** | Subida grande sin pico de memoria. Con zero-knowledge el servidor ya **no cifra**; el test afirma pico bajo por worker. **L4 manual.** | L4 | ❌xfail-manual |
| **M4** | Descargar un fichero → `Content-Type: application/octet-stream` + `Content-Disposition: attachment` + `X-Content-Type-Options: nosniff`. | L2 `stack_dev` | ⚠️ |
| **M5** | `cryptography`, `Django`, `requests`, `urllib3` por encima del umbral parcheado en `requirements.txt`. **Sigue abierto.** Umbral fijo, no `pip-audit`. | L0 | ❌ |
| **M6** | `CACHES['default']['OPTIONS']['IGNORE_EXCEPTIONS'] is False`; `master_key_guard` fail-closed (`strict_*`, `CacheUnavailable`→503). | L1 | ⚠️ |
| **M7** | `upload_file_combined` acepta POST/rechaza GET; `api_unlock_all_accounts` **eliminado**. Test: la ruta ya no resuelve. | L1 | ⚠️ |
| **M8** | Ver **Z10**. | L2 `stack_dev` | ⚠️ |
| **M9** | Registro → cuenta inactiva hasta verificar email; login desde IP nueva → TOTP. **Sigue abierto.** `is_active` es L2; el resto L4. | L2 + L4 | ❌ |
| **M10** | La cadena `getattr("settings"` no aparece en `middleware.py`. | L0 | ⚠️ |
| **M11** | `UserCrypto.verify_auth_key`/`Vault.verify_sub_auth_key` usan `check_password` (tiempo constante). | L1 | ⚠️ |
| **M12** | `detect_suspicious_request` **no** bloquea un POST cuya contraseña contiene `;`/`--`; usa ruta+método+tasa, no subcadenas. | L1 | ⚠️ |

### 4.5 Bugs laterales, correcciones sobre el terreno, hallazgo nuevo

| ID | Qué demuestra | Nivel / pila | Hoy |
|---|---|---|---|
| **BL1** | `REDIS_URL` y `REDIS_SESSIONS_URL` a bases distintas (`/1`, `/2`), leídas de variables de entorno **distintas** (la de sesiones ya no cae en `REDIS_URL`); ambas con contraseña en la pila real. | L0 + L1 | 🧪/⚠️ |
| **BL2** | `SESSION_ENCRYPTION_KEY` y `ENCRYPTION_KEY` definidas, no vacías y distintas (compara, no imprime). | L0 | ⚠️ |
| **T1** | `vite.config.ts` `manifest` + `outDir '../backend/static/dist'`; settings **sin** `DJANGO_VITE_ASSETS_PATH` (con `DJANGO_VITE_MANIFEST_PATH` en su lugar); `base.html` usa `src/main.tsx`; los servicios importan `API_BASE_URL`. | L0 | 🧪 (parcial) |
| **T1-d** | ⭐ `GET https://localhost/` → 200 y el `<script src=…>` del HTML responde 200. La cadena Vite→collectstatic→whitenoise→nginx **nunca se ha probado entera**. | L2 `stack_prod` | ⚠️ |
| **T2** | HSTS, X-Frame-Options, nosniff y Referrer-Policy aparecen **exactamente una vez**; Permissions-Policy y COOP también. Sin duplicados. | L2 `stack_prod` | ⚠️ |
| **T3** | Cliente nuevo sin token: `GET /api/csrf/` → **200 + cookie `csrftoken`** (`authentication_classes([])`). | L2 `stack_dev` | ⚠️ |
| **T4** | HSTS `max-age` corto (300 s) en local, `includeSubDomains`/`preload` desactivados bajo un año. Afirma la **cota superior**; jamás fuerza un valor largo (trampa 6). | L2 `stack_prod` | ⚠️ |
| **N1** | `POST /api/token/refresh/` con refresh válido en cookie → 200 + cookies reescritas (`CookieTokenRefreshView`). | L2 `stack_dev` | ⚠️ |
| **N2** | `PasswordGeneratorPage.tsx`/modales usan el CSPRNG de `passwordGenerator.ts`, **no** `Math.random()`. **Cerrado en el árbol** (commit `26b4c97`): pasa de xfail a test de regresión estático. | L0 | ⚠️ |

**Total: ~68 entradas** (15 zero-knowledge incl. 2 regresiones del 25 jul + 30 hallazgos + 2
bugs laterales + 5 correcciones + N1 + N2), cubriendo los 30 hallazgos, el esquema nuevo y los
bugs de integración ya encontrados.

---

## 5. Cobertura general (batería G)

Red anti-regresión para las ~9 400 líneas nuevas/cambiadas — 52 rutas, 68 vistas, 9 middleware,
`crypto.ts`, `UserCrypto`, `cryptoSession.ts`, `master_key_guard.py`, `jwt_cookies.py`.

| ID | Qué cubre | Nivel | Hoy |
|---|---|---|---|
| **G1** | Barrido de las **52 rutas** por `reverse()`; ninguna vista inalcanzable. Parametrizado. | L1 | ⚠️ |
| **G2** | ⭐ **Autorización por defecto:** cada ruta responde 401/403 sin autenticar, salvo lista blanca comentada (`/health/`, `/api/csrf/`, `/auth/login\|register/`, `/api/token/refresh/`, `/api/security/hibp-range/`, `/`, catch-all). Una vista nueva sin `permission_classes` rompe este test el mismo día. | L1 | ⚠️ |
| **G3** | El catch-all no traga la API: `GET /api/inventada/` → 404, no 200-HTML (generaliza N1). | L1 | ⚠️ |
| **G4** | Modelos: alta y round-trip de los 8 modelos, `__str__` no revienta, y borrar un usuario arrastra en cascada `PasswordEntry`, `EncryptedFile`, `UserCrypto`, `Vault`. | L1 | ⚠️ |
| **G5** | `generate_passwords`: longitud/cantidad/alfabeto respetados y sigue usando `secrets`. | L1 | ⚠️ |
| **G6** | Validadores: `CustomPasswordValidator` + cadena `AUTH_PASSWORD_VALIDATORS` aceptan/rechazan lo esperado (incluido el caso con `;`, cruce con M12). | L1 | ⚠️ |
| **G7** | Cadena de 9 middleware: una petición autenticada los atraviesa sin excepción, en las **dos** pilas. | L1 | ⚠️ |
| **G8** | Comandos: `setup_minio_buckets`, `cleanup_sessions`, `cleanup_orphans` corren sin excepción. | L1 | ⚠️ |
| **G9** | `makemigrations --check --dry-run`: sin cambios de modelo sin migrar. Las 0022-0026 son manuales a propósito (trampa 15). | L1 | ⚠️ |
| **G10** | `manage.py check --deploy` sin W009/DEBUG; en `stack_prod` sin W004/W008/W012/W016. | L1 `stack_prod` | ⚠️ |
| **G11** | ⭐ **`crypto.ts` build + tipos.** `npm run typecheck` y el bundle de vitest importan `crypto.ts` sin error. | L3 | ⚠️ |

### 5.1 Objetivo de cobertura

`pytest-cov` sobre `myapp/`, con umbral **por módulo**. `crypto.ts` con la cobertura de vitest
(`v8`), aparte.

| Ámbito | Objetivo |
|---|---|
| Núcleo — `models.py`, `utils/` (jwt_cookies, master_key_guard, request_utils, key_domain, vault_unlock, cache_utils), `authentication.py`, `validators.py` | **≥ 90 %** |
| `middleware.py` | **≥ 80 %** |
| `session_manager.py` | **≥ 70 %** |
| `views/` (68 vistas) | **≥ 65 %** |
| `minio_service.py` | **≥ 40 %** (sólo camino feliz) |
| `crypto.ts` + `passwordGenerator.ts` (vitest) | **≥ 90 %** |
| `demo/settings.py`, `migrations/`, `wsgi/asgi` | **excluidos** |
| **Global `myapp/`** | **≥ 75 %** |

`fail_under` **no se inventa**: la primera pasada mide, se fija en el valor real −2 puntos y sube
al cerrar Fase 3. Un umbral aspiracional que nadie alcanza acaba desactivado.

---

## 6. Configuración común: reglas duras

El punto de mayor riesgo. Los tests corren contra **la misma Redis y el mismo MinIO que la app
en marcha**, y los middleware escriben en ambos en cada petición.

**Módulo de settings de test:** `backend/myapp/tests/settings_test.py` (dentro del paquete que
sustituye a `tests.py`). Hace `from demo.settings import *` y **sólo** toca cinco cosas:

1. **Redis a la db 15**, `KEY_PREFIX='test'`. Las cachés reales son db 1 y 2 de la misma
   instancia: sin esto un test de rate limit escribe en los contadores de la app viva y un
   `cache.clear()` le borra la sesión a un usuario real.
2. **Bucket MinIO propio** (`MINIO_BUCKET_NAME='test-…'`): si no, los tests de ficheros dejan
   objetos con claves de test en el bucket de producción, indistinguibles de los buenos.
3. **Handlers de fichero del `LOGGING` → `NullHandler`.** `RotatingFileHandler` apunta a rutas
   **relativas**: con otro cwd, el logging revienta al configurarse y la suite entera falla por
   una razón ajena a lo que prueba.
4. **`DEBUG=False` fijo**, para que ninguna aserción dependa de con qué pila se lanzó.
5. Nada más.

> **Regla dura:** los tests que **afirman sobre configuración** (A2-a/b, A8-a, M6, BL1) importan
> **`demo.settings` explícitamente**, nunca `django.conf.settings`, que ya viene tocado por
> `settings_test`. Si M6 leyera `django.conf.settings`, comprobaría el override del test y daría
> verde con `IGNORE_EXCEPTIONS: True` intacto en producción: falso verde en el hallazgo que dice
> que la seguridad falla en abierto. **(Los L0 no importan Django en absoluto: leen
> `backend/demo/settings.py` como texto/AST, que es aún más estricto.)**

**Aislamiento entre casos:**

- Fixture `autouse`: `cache.clear()` en `default` y `sessions` **antes y después** de cada test
  (trampa 10).
- L1: rollback de `pytest.mark.django_db`. **L2 no tiene rollback**: fixture de sesión que borra
  usuarios de test y su cascada (incluido `UserCrypto` y objetos en el bucket de test).

**Orden y paralelismo — el fallo en cascada más probable:**

- **Prohibido `pytest-xdist`.** Los contadores de rate limit y el `master_key_guard` son estado
  global por IP/usuario en Redis; en paralelo se pisan.
- Rate limiting (A3-b, A4-c, A12-c) → `@pytest.mark.serial`, **al final**, con flush antes y
  después. Si no, agotan el presupuesto de auth de la IP y **todos los logins posteriores dan
  429**, que se lee como "40 tests rotos".

**Comprobaciones previas** (fallar pronto y claro):

- **Redis alcanzable.** Con `IGNORE_EXCEPTIONS: False` un Redis caído hace fallar tests que antes
  pasaban en silencio: el `conftest` lo comprueba y aborta con el motivo.
- **Permiso para crear la BD de test.** `myuser` es superusuario del `initdb`; si no, mensaje que
  remite a `--reuse-db`/`--keepdb`.
- **Qué pila está levantada.** El `conftest` de L2 la detecta y **salta** (no falla) los tests de
  la otra.

**Credenciales de fixture — tres restricciones simultáneas:**

- sin `;`/`--`/`DELETE` (el nuevo `detect_suspicious_request` puede señalizar; prudencia y cruce
  con G6);
- ≥ 12 caracteres (`MinimumLengthValidator` a 12);
- pasar `CustomPasswordValidator`.

**Fixtures zero-knowledge:** crear un usuario de test con bóveda utilizable exige material cripto
derivado en cliente (`kdf_salt`, `auth_key_hash`, `wrapped_vault_key`). Dos caminos:

- **L1/L2:** un helper que reproduce en Python la derivación de `crypto.ts` (Argon2id + HKDF con
  `argon2-cffi`, ya instalado) para sembrar `UserCrypto` por ORM. Vive en `conftest.py` y se
  prueba contra un **vector fijo compartido con Z4** (mismo `(pwd,salt)` → mismo `MK` en ambos
  lados): si Python y `crypto.ts` divergen, salta ese test, no 20 (trampa 14).
- **L3:** `crypto.ts` directamente, que es lo que se está probando.

---

## 7. Andamiaje

```
PLAN-DE-PRUEBAS.md               ← este documento, hermano de AUDITORIA-SEGURIDAD.md
pytest.ini                       ← raíz: marcadores + testpaths = tests/ (L0 y L2, host); NO configura Django
tests/
  conftest.py                    rutas del repo, helpers de lectura de ficheros
  l0/
    test_config_django.py        C5-a, A2-a, A2-b, T1(settings), BL1        ← [tanda 1]
    test_compose.py              A10-a, A11-a            (PyYAML)
    test_nginx.py                A12-a
    test_spa.py                  T1(vite/base/api), A2-d
    test_frontend_tokens.py      A1-a, N2
    test_secretos.py             BL1, BL2, .gitignore   (compara, nunca imprime)
    test_dependencias.py         M5  (xfail estricto)
    test_codigo_fuente.py        C4-a, A4-a, A8-b, M1(straggler, xfail), M10
  l2/
    conftest.py                  fixtures de pila, usuario+UserCrypto por ORM, limpieza Redis, detección de pila
    test_edge_tls.py             A2-c, A12-b, A12-c, T2, T4, T1-d, C5-b   stack_prod
    test_zk_ficheros.py          M2 ⭐, M4                                 stack_prod
    test_despliegue.py           C4-b, A10-b, A11-b                       stack_prod
    test_auth_http.py            C3, T3, N1, A1-b, A5, Z7                  stack_dev
    test_ratelimit_app.py        A3-b, A4-c                    serial     stack_dev
    test_zk_datos.py             A7, Z10, Z11, M3-a, M8, M9(is_active,xfail)  stack_dev
  l4_manual.py                   A6-b, M3-b, M9(email/TOTP)  (guiones en docstrings)
backend/
  pytest.ini                     ← in-container: DJANGO_SETTINGS_MODULE=myapp.tests.settings_test
  requirements-dev.txt           ← pytest, pytest-django, pytest-cov
  myapp/tests/                   ← SUSTITUYE tests.py (elimina el print(os.urandom(32)))
    __init__.py
    settings_test.py             Redis db 15, bucket propio, logging NullHandler
    conftest.py                  limpieza de caché, helper de derivación ZK, chequeos previos
    test_zk_modelos.py           Z5, Z6, Z8, Z12, C1(sin MasterKey), C2, M11
    test_settings.py             A8-a, C6(LEEWAY), M6, BL1   (lee demo.settings)
    test_middleware.py           A3-a, A4-b, M12, G7
    test_auth.py                 A5, A6-a
    test_g_rutas.py              G1, G2, G3
    test_g_modelos.py            G4
    test_g_cripto.py             G5
    test_g_validadores.py        G6
    test_g_comandos.py           G8, G9, G10
frontend/
  vitest.config.ts               entorno jsdom, cobertura v8 sobre src/services/*.ts
  src/services/crypto.test.ts    Z2, Z3, Z4, Z9, Z13, C6(AEAD), A8-b(KDF), G11
  src/services/passwordGenerator.test.ts   N2 (CSPRNG, sin sesgo)   ← nuevo, por N2 cerrado
```

Dos `pytest.ini`, uno por contexto: el de la raíz **no configura Django** (no puede); el de
`backend/` fija `DJANGO_SETTINGS_MODULE=myapp.tests.settings_test`.

`backend/myapp/tests.py` → paquete `backend/myapp/tests/`. Único fichero de producción que se
toca; desaparece con él el `print(os.urandom(32))` a nivel de módulo.

### 7.1 Dependencias nuevas

- **Host:** sólo `pytest`. `PyYAML` y `requests` ya instalados. Python host 3.12.
- **Contenedor:** `pytest`, `pytest-django`, `pytest-cov` en `backend/requirements-dev.txt` (no
  se instala en la imagen de producción). `argon2-cffi` ya está.
- **Frontend:** `vitest`, `@vitest/coverage-v8`, `jsdom` como `devDependencies`. `hash-wasm` ya
  está.
- Descartados: `factory_boy`, `freezegun`, `responses`, `pytest-xdist` (**prohibido** por el
  estado global de rate limit).

---

## 8. Trampas incorporadas al diseño

| # | Trampa | Cómo se refleja |
|---|---|---|
| 1 | Compose aplica override sin `-f` | Etiquetas de pila; `conftest` L2 detecta y salta la otra |
| 2 | `MinIOService()` a nivel de módulo | L1 sólo en contenedor; L0 nunca importa Django |
| 3 | Crear BD de test | `myuser` superusuario; plan B `--keepdb` documentado |
| 4 | nginx enmascara el rate limit de app | A3-b/A4-c por `web:8000`; A12-c por `:443` |
| 5 | Certificado autofirmado | `verify=False` + `urllib3.disable_warnings` |
| 6 | HSTS por host, ignora puerto | T4 sólo afirma cota superior; nunca emite valor largo |
| 7 | BD vacía, sin usuarios | Fixture crea usuario **con material ZK** por ORM |
| 8 | `/api/csrf/` daba 401 | T3, ya resuelto; el fixture usa cookie csrf del endpoint |
| 9 | M2 sin verificar | Test ⭐, partiendo de `smoke.py` adaptado al flujo ZK |
| 10 | Middleware escriben en Redis/BD | Fixture `autouse` que limpia entre casos |
| 11 | Bloqueo por subcadenas (M12) | Ya cerrado; se mantiene la regla de credenciales por prudencia |
| 12 | `SECURE_SSL_REDIRECT`→301 en HTTP | `stack_dev` usa `web:8000` con `TLS=false` |
| 13 | `openssl -subj` en Git Bash | No aplica: certificados ya existen |
| 14 | Derivación ZK duplicada Python↔TS | Vector fijo compartido (Z4) valida que el helper del `conftest` no diverge de `crypto.ts` |
| 15 | Migraciones 0022-0026 manuales | G9 confirma que el estado del modelo cuadra con ellas, sin regenerarlas |
| 16 | `DJANGO_VITE_ASSETS_PATH` en un **comentario** de `settings.py` | El L0 de T1 usa **nombres asignados por AST**, no `str in source`: el ajuste no está *asignado* aunque el string aparezca en la nota que explica su retirada |

---

## 9. Orden de implementación

De menor a mayor coste, con confirmación tras cada bloque y **sin encadenar fases**. Se trabaja
en **tandas de 3 ficheros**: crear → parar → dar el prompt de continuación.

1. **`PLAN-DE-PRUEBAS.md`** + `pytest.ini` (raíz) + primer L0 (`test_config_django.py`). ← tanda 1
2. **Resto de L0** (host, sin Docker). Convierte en regresión lo hecho en Fases 0-1 y deja
   rojo-marcado M5 y el straggler de M1.
3. **L3 vitest** sobre `crypto.ts` y `passwordGenerator.ts`. Único camino para verificar la
   corrección del núcleo zero-knowledge; el servidor no puede.
4. **Configuración común de L1**: `settings_test.py` + `conftest.py` (con el helper de derivación
   ZK validado contra el vector de Z4) + `backend/pytest.ini`, y una pasada en vacío que sólo
   demuestre el aislamiento. **Antes de escribir ningún test L1. Aquí se para y se da el comando
   para levantar la pila.**
5. **L1 de hallazgos y zero-knowledge** (sustituye `tests.py`).
6. **L1 batería G** + primera medición de cobertura; sólo entonces se fija `fail_under`.
7. **L2** por bloques: primero despliegue, M2 ⭐ y edge/TLS (`stack_prod`), luego `stack_dev`.
   Rate limiting, el último y en serie. **Cada cambio de pila → parar y dar el comando.**
8. **L4**: guiones manuales (A6-b, M3-b, M9).

---

## 10. Cómo ejecutar

```bash
# L0 — host, sin Docker
pip install pytest
pytest tests/l0 -v                       # verde, con XFAIL (M5, straggler M1)
pytest tests/l0 -m fase3 --runxfail -v   # rojo a propósito: la deuda de Fase 3
pytest -ra -q                            # el resumen de xfail = inventario de deuda

# L3 — host, sin Docker (núcleo zero-knowledge del cliente)
cd frontend && npm i -D vitest @vitest/coverage-v8 jsdom
npx vitest run --coverage

# L1 — dentro del contenedor
docker compose exec web pip install -r requirements-dev.txt
docker compose exec web pytest myapp/tests -v
docker compose exec web pytest myapp/tests \
  --cov=myapp --cov-report=term-missing:skip-covered --cov-report=html

# L2 — host contra la pila (rate limiting en serie y al final)
pytest tests/l2 -m "stack_prod and not serial" -v
pytest tests/l2 -m "stack_dev  and not serial" -v
pytest tests/l2 -m serial -v

# L4 — listar manuales pendientes
pytest -m manual --collect-only -q
```

**Criterio de éxito del plan** (no de los hallazgos):

1. `pytest` sin argumentos termina **verde** hoy, con pocos XFAIL (M5, M9, straggler M1) cuyos
   motivos, leídos en orden, son la deuda de Fase 3 que queda.
2. **La primera ejecución en contenedor convierte los ~50 ⚠️ en ✅ o descubre un fallo real de la
   rearquitectura zero-knowledge.** Ése es el valor: nadie ha arrancado la pila desde que empezó
   la Fase 1.
3. `crypto.ts` supera el 90 % de cobertura vitest, con Z2/Z3/Z4/Z9 verdes.
4. El día que cierre Fase 3, la suite se pone **roja** por XPASS estricto hasta retirar los
   marcadores de M5/M9.
5. **Aislamiento:** ejecutar la suite dos veces seguidas da el mismo resultado y las claves de
   Redis db 1/2 y el bucket de producción quedan intactos.

---

## 11. Restricciones respetadas

- Sin `git add` ni `git commit`.
- Ningún hallazgo arreglado. M5, M9 y el straggler de M1 se documentan y se paran. **N2 ya lo
  cerró el usuario** (commit `26b4c97`); aquí sólo se anota y se cubre con un test de regresión.
- Esquema de BD intacto. Único fichero de producción tocado: `myapp/tests.py` → paquete.
- Ninguna credencial nueva versionada; los tests de `.env` comparan sin imprimir valores.
- Dependencias nuevas separadas: `backend/requirements-dev.txt` y `devDependencies` del frontend.
- `AUDITORIA-SEGURIDAD.md` sólo se toca para **marcar cobertura de tests** en §2 (🧪 escrito /
  ✔️ verificado); no se cambia el estado de remediación de ningún hallazgo.
