# Auditoría de seguridad — Gestor de Contraseñas

**Proyecto:** Django 5.1 + DRF + JWT / React-Vite / PostgreSQL / Redis / MinIO / Docker
**Rama auditada:** `tokens` (último commit previo a la intervención: `add989a`)
**Fecha:** 21 de julio de 2026 (actualizado el 25 de julio de 2026)
**Estado:** Fase 0 y Fase 1 aplicadas. **Fase 2 (rearquitectura zero-knowledge) COMPLETA:
pasos 21–28 aplicados, sin commitear** — verificación estática completa; **verificación en
contenedor y en navegador iniciada (25 jul), ver §7·octies y §7·nonies.** El **paso 28**
(SSE-S3 de MinIO + retirada de la Fernet de aplicación + purga del `FileField` legado) está
aplicado y el flujo de ficheros se ejerció de extremo a extremo en navegador. Fase 3 pendiente.

> **Aviso de estado (25 jul 2026).** Todo lo que este documento marca como aplicado en las
> Fases 1 **y 2** se comprobó **de forma estática** (`py_compile` en el backend, `npx tsc -b` en el
> frontend —el typecheck real; `tsc --noEmit` da falso "limpio" porque el tsconfig raíz sólo tiene
> `references`—, `nginx -t`, pruebas en aislado del código real con dobles). **El 25 jul se levantó
> la pila por primera vez** desde que empezó la Fase 1: la migración `0025` (purga del paso 26) se
> aplicó en contenedor sin error sobre BD fresca, y aparecieron **dos fallos de integración de
> runtime que el estático no detecta** (AES-GCM `additionalData`; falta del flujo de desbloqueo),
> ya corregidos — detalle y estado de confirmación en **§7·octies**. El resto de criterios de
> aceptación de §10 (curl de cabeceras, rate-limit, `pg_dump`, integridad AEAD…) siguen pendientes.
> Nada de la Fase 1 ni de la Fase 2 está commiteado: los commits los gestiona el usuario.
>
> **Lo aplicado de la Fase 2 está en §7·quater** (análogo a §7·bis). Cuando el código y el
> diseño de este documento discrepen por lo ya implementado, **manda el código**; la
> arquitectura objetivo de §8 sigue siendo la referencia de diseño.

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
| C1 | `hashed_key` es la clave de cifrado, no un hash | C | ✅ **Cerrado por construcción (Fase 2, pasos 21–23)**; `MasterKey` y campos v1 **purgados (paso 26)** | Fase 2 |
| C2 | Salt global constante, en git | C | ✅ **Cerrado por construcción (Fase 2, paso 21: `kdf_salt` por usuario)** | Fase 2 |
| C3 | Bypass completo de la clave maestra | C | ✅ **Cerrado por construcción (Fase 2, paso 23: el servidor ya no descifra)**; análisis reimplementado **en cliente (paso 27)**, endpoints v1 retirados | Fase 2 |
| C4 | Secretos y metadatos por stdout | C | ✅ Cerrado | **Fase 0** |
| C5 | `SECRET_KEY` por defecto + `DEBUG=True` | C | ✅ Cerrado | **Fase 0** |
| C6 | Cifrado sin autenticar; `LEEWAY` de 300 s | C | ✅ **AEAD cerrado (Fase 2: AES-256-GCM en todo)**; **LEEWAY 30 s ✅ Fase 1** | Fase 2 |
| A1 | JWT en `localStorage`/`sessionStorage` | A | ✅ **Cerrado (Fase 1, paso 8)** | Fase 1 |
| A2 | Sin CSP; cookies sin `HttpOnly` | A | ✅ **Cerrado (Fase 1, pasos 8 y 9)** | Fase 1 |
| A3 | Fuerza bruta ilimitada de la maestra | A | ✅ **Cerrado (Fase 1, paso 11)** | Fase 1 |
| A4 | `X-Forwarded-For` sin validar (**10** copias) | A | ✅ **Cerrado (Fase 1, paso 10)** | Fase 1 |
| A5 | Logout no invalida el refresh token | A | ✅ **Cerrado (Fase 1, pasos 12 y 8)** | Fase 1 |
| A6 | Enumeración de usuarios por temporización | A | ✅ **Cerrado (Fase 1, paso 13)** | Fase 1 |
| A7 | `/api/accounts/` devuelve la bóveda cifrada entera | A | ✅ **Cerrado (Fase 2, paso 23: devuelve blob opaco AEAD)** | Fase 2 |
| A8 | PBKDF2 con 100 000 iteraciones; sin Argon2 | A | ✅ **Argon2id en cuentas (Fase 1) y en la derivación de bóveda (Fase 2, `deriveMasterKey` en cliente)** | Fase 1/2 |
| A9 | Las bóvedas privadas no protegen nada | A | ✅ **Cerrado (Fase 2, paso 24: VaultSubKey + marcador en servidor)** | Fase 2 |
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
| M8 | Imposible rotar la clave maestra | M | ✅ **Cerrado (Fase 2, paso 25: rotación zero-knowledge, re-envuelve la VaultKey sin re-cifrar)** | Fase 2 |
| M9 | Sin MFA ni verificación de email | M | ❌ Abierto | Fase 3 |
| M10 | `getattr("settings", …)` sobre la cadena literal | M | ❌ Abierto | Fase 3 |
| M11 | Comparación de secretos con `==` | M | ✅ Cerrado | **Fase 0** |
| M12 | `SecurityLoggingMiddleware` bloquea por subcadenas | M | ✅ **Cerrado (Fase 1, paso 18)** | Fase 1 |

Además se corrigieron en la Fase 0 dos **bugs laterales** detectados durante la auditoría,
sin identificador propio: la caché `sessions` compartía base de datos Redis con la caché
general, y `SESSION_ENCRYPTION_KEY` reutilizaba `ENCRYPTION_KEY`. Ver §7.

---

## 3. Hallazgos críticos en detalle

### C1 — `MasterKey.hashed_key` no es un hash: es la clave de cifrado real ✅ CERRADO POR CONSTRUCCIÓN EN FASE 2

> **Estado (24 jul 2026, §7·sexies).** El esquema v2 (`UserCrypto`) guarda `Argon2id(AuthKey)`
> vía `make_password` y un `wrapped_vault_key` opaco (AES-256-GCM); el servidor ya **no** tiene
> ninguna clave de descifrado. El modelo `MasterKey` y todos los campos v1 se **purgaron en el
> paso 26** (migración `0025` destructiva); el texto de abajo describe el modelo legado ya
> eliminado. El residuo de `api_delete_vault` se cerró en el paso 25.

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

### C2 — Salt global, constante y publicada en git ✅ CERRADO POR CONSTRUCCIÓN EN FASE 2

> **Estado (24 jul 2026).** `UserCrypto.kdf_salt` es **por usuario** (base64, generado en el
> cliente con `generateSalt`), y la bóveda privada tiene su `sub_kdf_salt` propio. La sal global
> de abajo pertenece al modelo legado (`MasterKey`/`PasswordEntry.salt`), que muere en 26/27.

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

### C3 — Bypass completo de la clave maestra ✅ CERRADO POR CONSTRUCCIÓN EN FASE 2

> **Estado (24 jul 2026).** La capacidad que estos endpoints ejercían —que el servidor pueda
> descifrar sin la maestra— **ya no existe en v2**: `api_accounts` devuelve blobs opacos y el
> descifrado ocurre en el cliente. Los dos endpoints v1 de `security_views.py` (y el `verify_master_key`
> crudo de su código muerto) se **eliminaron en los pasos 26/27**; el análisis de seguridad se
> reimplementó **en cliente** (paso 27, §7·septies), con HIBP vía proxy k-anonimato que no descifra.

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

### C6 — Cifrado sin autenticar ✅ AEAD CERRADO EN FASE 2 · ✅ LEEWAY cerrado en Fase 1

> **Estado (24 jul 2026).** Todo el cifrado v2 es **AES-256-GCM** (AEAD): entradas, envoltura de
> claves y subclaves, y ficheros por chunks. El tag detecta manipulación y una clave equivocada
> **falla el descifrado** en vez de devolver basura (WebCrypto lanza en `aesGcmDecrypt`). La
> AAD por entrada (`user_id || client_id || crypto_version`) impide el swap de blobs entre filas.
> `encryption_utils.py` (AES-CFB/ChaCha20 legado) **purgado en el paso 27** (queda sólo el generador CSPRNG).

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

### A7 — La bóveda cifrada completa en cada petición ✅ CERRADO EN FASE 2 (paso 23)
[password_views.py](backend/myapp/views/password_views.py) — `/api/accounts/` ahora devuelve
sólo `{ id, client_id, vault_id, crypto_version, ciphertext }`: un blob opaco AES-256-GCM sin
sal (la sal es por usuario en `UserCrypto`, no viaja por entrada) y sin material que permita un
ataque offline. Las entradas de bóvedas privadas bloqueadas se **omiten** de la respuesta (A9).
El texto original describía el esquema legado.

### A8 — Derivación de claves insuficiente ✅ CERRADO (Argon2 para cuentas en Fase 1; derivación de bóveda con Argon2id en Fase 2)

> **Estado (24 jul 2026).** La derivación de la maestra y de las contraseñas de bóveda ya no es
> PBKDF2: es **Argon2id** en el cliente (`deriveMasterKey`, hash-wasm, `KDF_PARAMS` en `crypto.ts`),
> con sal por usuario/por bóveda. Las cinco derivaciones PBKDF2 legadas de abajo mueren en 26/27.
[encryption_utils.py](backend/myapp/encryption_utils.py),
[models.py](backend/myapp/models.py) — PBKDF2-SHA256 con **100 000 iteraciones** en las
cinco derivaciones del código (OWASP 2023 recomienda 600 000). `argon2-cffi` está instalado
pero `PASSWORD_HASHERS` no se configura, así que Django usa PBKDF2 por defecto también para
las contraseñas de cuenta.

### A9 — Las bóvedas privadas no protegen nada ✅ CERRADO EN FASE 2 (paso 24)
[password_views.py](backend/myapp/views/password_views.py),
[vault_unlock.py](backend/myapp/utils/vault_unlock.py) — El `vault_already_unlocked` de confianza
del cliente **se eliminó**. Cada bóveda privada v2 tiene su **VaultSubKey** (32 B) envuelta bajo
`SubEncKey = HKDF(Argon2id(vault_password, subSalt),"enc")`: su contenido va cifrado con una clave
que la maestra por sí sola no deriva. Como defensa en profundidad, un **marcador de desbloqueo en
servidor** (fail-closed, TTL 15 min) gobierna la entrega de ciphertext/metadatos; se pone tras
probar posesión de la subclave (`guard_vault_auth_key`, bloqueo exponencial por bóveda). Ver
§7·quater y [[paso24-bovedas-privadas]].

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
| **M8** ✅ | Imposible rotar la clave maestra | **Cerrado en Fase 2 (paso 25):** `change_master_key` verifica la maestra actual con `guard_auth_key` y reemplaza `UserCrypto`; `rotateMasterPassword` re-envuelve la **misma** VaultKey con la EncKey nueva (sin re-cifrar la bóveda ni tocar las privadas), y `masterKeyService.changeMasterKey` queda cableado. Ver §7·quinquies. |
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

## 7·quater. Cambios aplicados en la Fase 2 (pasos 21–24b)

**Aplicada, sin commitear, verificada sólo en estático** (`py_compile` en el backend, `npx tsc
-b` en el frontend; **la pila no se ha levantado**). Rama `tokens`. Es la rearquitectura
criptográfica de §8: el servidor deja de poder descifrar. Todo es **aditivo** — los modelos y la
cripto legada (`MasterKey`, `Vault.vault_password_hash/vault_salt`, `encryption_utils`, la capa
Fernet de MinIO) siguen **intactos** hasta la purga de los pasos 26/27.

### Ficheros nuevos de la Fase 2
`backend/myapp/utils/vault_unlock.py` (paso 24, marcador de desbloqueo),
`backend/myapp/migrations/0024_vault_subkey_fields.py` (paso 24, a mano),
`frontend/src/services/crypto.ts` (paso 22, cripto de cliente pura),
`frontend/src/services/cryptoSession.ts` (paso 22, claves en memoria).
Migraciones previas de la Fase 2 escritas a mano: `0022` (UserCrypto + `crypto_version`/`ciphertext`
en PasswordEntry/EncryptedFile) y `0023` (`client_id`). La `0024` es aditiva y a mano **a
propósito**: `makemigrations` arrastraría la reevaluación de la sal global (C2) sobre
`masterkey.salt`/`passwordentry.salt`, churn que muere en la purga.

### Pasos 21–23 — modelos aditivos, cripto de cliente y endpoints sobre blobs opacos

**Modelos** ([models.py](backend/myapp/models.py)). Nuevo `UserCrypto(user 1:1, kdf_salt,
kdf_params, auth_key_hash, wrapped_vault_key, crypto_version=2)`: el servidor guarda
`Argon2id(AuthKey)` (vía `make_password`/`PASSWORD_HASHERS`, `set_auth_key`/`verify_auth_key`) y el
`wrapped_vault_key` opaco; **nunca** la maestra, la MK, la EncKey ni la VaultKey. `PasswordEntry` y
`EncryptedFile` ganan `crypto_version` (1 = legado, 2 = blob AEAD), `ciphertext` y `client_id`
(UUID único). El `client_id` va en la **AAD** por entrada (`user_id || client_id || crypto_version`)
como identidad estable anti-swap: impide que una escritura en BD copie a la vez ciphertext+client_id
de otra fila.

**Cripto de cliente** ([crypto.ts](frontend/src/services/crypto.ts), funciones **puras** y
testeables). `deriveMasterKey` (Argon2id vía **hash-wasm**, `KDF_PARAMS`), `deriveAuthKey`/
`deriveEncKey` (HKDF-SHA256, info `"auth"`/`"enc"`), `wrapVaultKey`/`unwrapVaultKey`,
`encryptEntry`/`decryptEntry` (AES-256-GCM, `buildEntryAAD`), `setupUserCrypto`, `unlockVault`,
más las de ficheros (`encryptFile`/`decryptFile` por chunks, `wrapFileKey`/`unwrapFileKey`).
[cryptoSession.ts](frontend/src/services/cryptoSession.ts) guarda las claves **sólo en memoria**
(VaultKey principal + `Map` de subclaves) con auto-bloqueo por inactividad, y expone
`encryptEntryForVault`/`decryptEntryForVault` con **selección segura de clave** por `keyDomainId`
(subclave si la bóveda está registrada; si no, la principal — AES-GCM falla el tag con la clave
equivocada, nunca devuelve basura).

**Endpoints zero-knowledge.** `masterkey_views.py` reescrito entero sobre `UserCrypto`:
`setup_master_key` (registra el material), `check_master_key`, `get_crypto_params`
(`GET /api/master-key/params/`: devuelve `kdf_salt`/`kdf_params`/`wrapped_vault_key` al propio
dueño; es opaco sin su maestra), `verify_master_key` (prueba de posesión de la AuthKey bajo
`guard_auth_key`, **no** es oráculo de descifrado), `change_master_key` (**501**, paso 25).
`password_views.py`: `api_accounts` devuelve blobs opacos (A7); `add`/`update`/`delete`/`move`
operan sobre `ciphertext`+`client_id`+`crypto_version` sin ver texto claro. **Endpoints
eliminados** (paso 23): `/api/unlock-password/<id>/` y `/api/unlock-all-accounts/` —el servidor ya
no descifra, así que no tienen sentido. `guard_auth_key` (esquema v2) se añadió a `master_key_guard`
junto al `guard_master_password` legado, generalizando el núcleo `_guard(..., scope, invalid_message)`.

### Paso 24 + 24b — bóvedas privadas zero-knowledge (A9)

**Migración 0024** (a mano, aditiva). `Vault` gana `sub_kdf_salt`, `sub_kdf_params`,
`sub_auth_key_hash`, `wrapped_vault_subkey`, `vault_crypto_version` (1 = legado, 2 = subclave
zero-knowledge), más `set_sub_auth_key`/`verify_sub_auth_key`. `vault_password_hash`/`vault_salt`
legados **intactos**.

**Diseño.** Cada bóveda privada v2 tiene su **VaultSubKey** (32 B) envuelta bajo
`SubEncKey = HKDF(Argon2id(vault_password, subSalt),"enc")`. Es la misma construcción que la
principal (§8) pero con la **contraseña del vault** como secreto: un segundo factor que la maestra
por sí sola no cubre. El servidor guarda `Argon2id(SubAuthKey)` (prueba de posesión) y el
`wrapped_vault_subkey` opaco; nunca ve la contraseña del vault ni la SubEncKey.

**Gate A9 = marcador de desbloqueo en servidor** ([vault_unlock.py](backend/myapp/utils/vault_unlock.py)),
que sustituye al `vault_already_unlocked` de confianza del cliente (**eliminado**).
`mark_vault_unlocked`/`is_vault_unlocked`/`clear_vault_unlock` (TTL 15 min, alineado con el
auto-bloqueo de `cryptoSession`) y `guard_private_vault_access` (devuelve `None` o un `JsonResponse`
403 `VAULT_LOCKED` / 503). **Fail-closed**: la comprobación es `strict_*` (si Redis no responde,
deniega, M6); el borrado es `lenient`. La prueba de posesión es `guard_vault_auth_key` en
`master_key_guard`, con `scope='vault:<id>'` → **bloqueo exponencial propio por bóveda** (equivocar
la contraseña de una bóveda no bloquea la maestra ni las demás).

**Endpoints** ([vault_views.py](backend/myapp/views/vault_views.py)):
- `api_create_vault` — si `is_private`, recibe material opaco (`sub_kdf_salt`, `sub_kdf_params`,
  `sub_auth_key`, `wrapped_vault_subkey`), marca `vault_crypto_version=2` y **deja la bóveda
  desbloqueada** (best-effort).
- `api_vault_crypto_params` — **nuevo** `GET /api/vaults/<id>/crypto-params/`, espeja a
  `/api/master-key/params/`.
- `api_unlock_vault` — prueba de posesión (`sub_auth_key`) → marcador (fail-closed).
- `api_change_vault_password` — rotación zero-knowledge: re-envuelve la **misma** VaultSubKey,
  no re-cifra entradas; verifica la actual e invalida el marcador.
- `api_convert_vault_privacy` — **paso 24b**, público↔privado con **re-cifrado en lote** de todas
  las entradas (cambia el dominio de clave), transacción atómica, exige el mapa `ciphertexts`
  **completo** (código `REENCRYPT_INCOMPLETE` si falta alguna). Ya **ROUTED**
  (`/api/vaults/<id>/convert-privacy/`).

**Gates** en `api_vault_passwords` y `api_accounts` (oculta las entradas de privadas bloqueadas), y
en `add`/`move` de [password_views.py](backend/myapp/views/password_views.py). Los `move` que
cambian de dominio de clave exigen `ciphertext`/`ciphertexts` re-cifrado o devuelven
`REENCRYPT_REQUIRED` (400): la seguridad se centraliza en el backend.

**Frontend.** `crypto.ts`: `setupVaultSubKey`/`unlockVaultSubKey`/`rotateVaultPassword` (puras).
`cryptoSession`: `Map` de subclaves + `keyDomainId`. `vaultService`: `create`/`unlock`/`change`/
`convert` reescritos zero-knowledge; los `move` **delegan** en `passwordService` (de paso se
arregló la URL rota `/api/vaults/batch-move-passwords/`). `passwordService`: cifra/descifra con la
clave de la bóveda de cada entrada; `reencryptForMove` re-cifra al cambiar de dominio.

### Residuos declarados de la Fase 2 (ciérralos o decláralos, no los ocultes)

- ~~`api_delete_vault` valida contra el `MasterKey` legado~~ → **RESUELTO en el paso 25** (§7·quinquies):
  migrado a `guard_auth_key`/`UserCrypto` y con re-cifrado al mover contenido fuera de una privada.
- **`convert-privacy` no tiene disparador de UI**: backend + `vaultService.convertVaultPrivacy`
  listos, pero ningún componente lo llama (candidato: `ManageVaultModal`). Cablearlo es UX aparte.
- **`update_password`/`delete_password` de una entrada de bóveda privada NO exigen el marcador**
  (autorizadas por sesión, coherente con "sin maestra" de la Fase 2): una sesión robada podría
  corromper/borrar pero **no leer** (sin subclave). Bajo riesgo, declarado.
- **`security_views.py` conserva un `verify_master_key` crudo sin guardián** bajo el 501 de F0-3
  (residuo de Fase 1): al revivirlo en el paso 27 hay que meterle guardián.
- Legado aún vivo hasta 26/27: `MasterKey`, `Vault.vault_password_hash/vault_salt`, la cripto de
  `encryption_utils`, la capa Fernet de MinIO, y las cinco derivaciones PBKDF2.

Ver [[paso24-bovedas-privadas]] y [[pendientes-cierre-fase1]] en la memoria.

---

## 7·quinquies. Cambios aplicados en la Fase 2 — paso 25 (rotación de la maestra, M8)

**Aplicado, sin commitear, verificado sólo en estático** (`py_compile` backend + `npx tsc -b`
frontend en verde; **falta Docker**). Rama `tokens`.

### Rotación de la clave maestra (M8)
Rotar es **zero-knowledge y sin re-cifrar la bóveda**: el cliente
([crypto.ts](frontend/src/services/crypto.ts) `rotateMasterPassword`) desenvuelve la **misma**
VaultKey con la EncKey actual y la re-envuelve con la EncKey nueva, deriva el material nuevo
(`kdf_salt`, `kdf_params`, AuthKey, `wrapped_vault_key`) y **también** la prueba de posesión de la
maestra actual (`currentAuthKey`). `change_master_key`
([masterkey_views.py](backend/myapp/views/masterkey_views.py)) deja de responder 501: verifica la
actual con **`guard_auth_key`** (mismo bloqueo exponencial por usuario que A3; nunca descifra nada)
y reemplaza el material de `UserCrypto`. `masterKeyService.changeMasterKey` cableado (antes hacía un
POST vacío). **Como la VaultKey no cambia, la sesión de desbloqueo en curso sigue válida** y las
bóvedas privadas —envueltas bajo su propia SubEncKey— no se tocan.

### Borrado de bóveda migrado a auth zero-knowledge + re-cifrado (residuo de §7·quater)
`api_delete_vault` ([vault_views.py](backend/myapp/views/vault_views.py)) ya **no** valida contra
el `MasterKey` legado (que un usuario v2 no tiene): recibe la AuthKey derivada en el cliente
(`masterKeyService.deriveAuthProof`) y prueba posesión con `guard_auth_key`. Además, mover el
contenido de una **bóveda privada v2** al borrarla cambia de dominio de clave: ahora exige y aplica
el **re-cifrado en lote** (`ciphertexts`), en **transacción atómica**, gateando las privadas
implicadas y devolviendo `REENCRYPT_REQUIRED` (fail-closed) si falta algún blob — nunca corrompe. El
criterio de dominio de clave se extrajo a un util compartido nuevo,
[utils/key_domain.py](backend/myapp/utils/key_domain.py) (`is_private_v2`,
`reencrypt_required_response`), que reemplaza los helpers locales duplicados de `password_views.py`.
El frontend (`vaultService.deleteVault`) deriva la AuthKey, detecta la privada por
`crypto-params`, exige la bóveda desbloqueada y re-cifra cada entrada para el dominio del destino.

### Residuos declarados del paso 25
- **`convert-privacy` sigue sin disparador de UI** (residuo heredado de 24b, no del 25).
- **Borrado de bóveda con destino privado no desbloqueado**: `deleteVault` sólo re-cifra cuando la
  bóveda **origen** es privada v2 (caso "borrar una privada y conservar sus entradas"). Mover
  contenido de una bóveda **pública a una privada** al borrarla, o a una privada de destino que no
  esté desbloqueada, cae en el backend con `REENCRYPT_REQUIRED`/`VAULT_LOCKED` (fail-closed, sin
  corrupción); la UI muestra el error y el usuario mueve las entradas antes de borrar. Bajo riesgo,
  declarado.
- Rotación de la maestra **para usuarios legados** (sólo `MasterKey`, sin `UserCrypto`): devuelve
  400 "No tienes una clave maestra configurada" — es correcto (deben migrar a v2 en el paso 26).

---

## 7·sexies. Cambios aplicados en la Fase 2 — paso 26 (purga del legado)

**Aplicado, sin commitear, verificado sólo en estático** (`py_compile` de los 13 ficheros Python
tocados en verde; frontend **no tocado** → `npx tsc -b` sin cambios). Rama `tokens`. No hay datos
reales (BD y volúmenes vacíos): la ruptura está aceptada, así que el 26 es **purga destructiva** del
esquema v1 + limpieza de todas sus referencias.

### Migración `0025_purge_legacy_crypto` (a mano, DESTRUCTIVA)
Primera migración no aditiva de la Fase 2. Dependencia `0024`. Elimina:
- **Modelo `MasterKey`** entero (`DeleteModel`) — cierra por purga el fallo raíz C1 (`hashed_key`
  era la clave de cifrado) y la sal global C2 (`salt` con `default=get_random_string(32)` congelado
  en 0007–0021).
- **`PasswordEntry`**: `website`, `username`, `encrypted_password`, `encryption_algorithm`, `salt`,
  `iv_or_nonce`, `encrypted_key` (esquema v1: sitio/usuario en claro + cripto de servidor). El
  sitio, el usuario y la contraseña ya viajaban cifrados dentro de `ciphertext`.
- **`EncryptedFile`**: `title`, `salt`, `iv_or_nonce`, `algorithm`, `encrypted_key`.
- **`Vault`**: `vault_password_hash`, `vault_salt` (contraseña de bóveda privada legada, PBKDF2 en
  servidor; las privadas v2 usan `wrapped_vault_subkey`).

Escrita a mano como 0022–0024: `makemigrations` no corre fiable fuera de Docker y arrastraría la
reevaluación de la sal global. Sobre BD vacía aplica sin migrar datos.

### Referencias al legado limpiadas (antes de la purga, o no compila)
- **`models.py`**: eliminados `MasterKey`, los métodos `set_vault_password`/`verify_vault_password`
  de `Vault`, y los imports que quedaban sin uso (`get_random_string`, `PBKDF2HMAC`, `hashes`,
  `base64`, `hmac`, `os`). `__str__` de `PasswordEntry`/`EncryptedFile` ya no nombran campos en
  claro (usan `id`).
- **Bloqueante de import-time (`forms.py`)**: `PasswordUpdateForm`, `PasswordForm` y
  `EncryptedFileForm` (flujo server-rendered v1) tenían `Meta.fields` con campos purgados →
  `FieldError` **al importar** (y `general_views.py` importa `forms.py`). Se eliminaron los tres;
  quedan `UserRegisterForm` y `SettingsForm` (el único importado).
- **`security_views.py`** (corte 26/27, ver abajo): quitados los imports `MasterKey` y
  `decrypt_password`; **borrado el código muerto** bajo los `501` de `api_security_analysis` y
  `api_check_single_password_breach` (era el `verify_master_key` crudo sin guardián, residuo de
  Fase 1: **cerrado aquí**). Los stubs 501 y las funciones puras reutilizables se conservan. El
  `api_security_recommendations` **vivo** dejó de filtrar por `encryption_algorithm`.
- **`dashboard_views.py`**: `strong_passwords`/`security_score` ya no dependen de
  `encryption_algorithm` (en v2 todo es AES-256-GCM); el fallback de `recent_activity` ya no lee
  `pwd.website`/`file.title` (metadatos cifrados).
- **`auth_views.py`**: `has_master_key` pasa de `hasattr(user,'masterkey')` a
  `hasattr(user,'crypto')` (`UserCrypto`) en login y `check_auth` — de paso corrige una
  incoherencia latente (antes reportaba `False` para un usuario v2 ya configurado).
- **`master_key_guard.py`**: eliminado `guard_master_password` (legado, sin llamadores vivos).
- **`password_views.py`/`file_views.py`**: `create` deja de escribir las columnas legadas `''`.
- **`admin.py`**: sin `register(MasterKey)`. **`cleanup_orphans.py`**: loguea por `id`/`file_path`
  en vez de `title`. **`vault_views.py`**: `api_vault_search` ya no busca por `website`/`username`
  (los campos no existen y estaba roto con `Vault.Q`); sólo busca bóvedas por nombre y devuelve
  `passwords: []` (la búsqueda de contenido es en cliente).

### Corte 26 / 27 (declarado)
- **En el 26** se eliminó el código muerto de `security_views` porque referenciaba `MasterKey` — con
  ello el residuo *"`verify_master_key` crudo sin guardián"* queda **cerrado en el 26**, no en el 27.
- **Se queda para el 27**: `encryption_utils.py` entero (`decrypt_password` + AES-CFB/ChaCha20)
  sigue **intacto pero YA SIN NINGÚN CONSUMIDOR** (nadie lo importa tras el 26); se purga al rehacer
  el análisis de seguridad **en cliente** (reactivar los dos 501).
- **Se queda para el 28**: `EncryptedFile.encrypted_file` (FileField) y la capa Fernet at-rest de
  MinIO.

### Andamiaje / aviso de migración (sub-tarea 3 del paso 26)
**No se construye asistente de export/reimport**: no hay registros v1 (BD y volúmenes vacíos) y la
ruptura de datos está aceptada. Cualquier bóveda v1 previa a esta rearquitectura **debe
considerarse comprometida** (el servidor podía descifrarla, C1). La purga es directa.

### Residuos declarados del paso 26 (no ocultar)
- **`encrypted_file` (FileField) de `EncryptedFile`** se conserva hasta el paso 28 (retirada de la
  capa Fernet/MinIO). En v2 el objeto vive en `file_path`; el FileField queda vacío.
- **Plantillas Django legadas** (`accounts.html`, `file_list.html`, `unlocked_password.html`,
  `delete_file.html`) siguen referenciando campos purgados, pero **ninguna vista las renderiza**
  (el único `render` vivo es `base.html`): código muerto del flujo pre-SPA, sin efecto en runtime
  ni en `py_compile`. Limpieza cosmética para Fase 3 (M7).
- **`security_score` del dashboard** es ahora un marcador basado en el conteo (todas las entradas
  v2 son AES-256-GCM). El análisis real de fortaleza llega en el paso 27 (en cliente).
- `api_vault_search` devuelve `passwords: []`: la búsqueda por contenido pasa a ser 100% cliente.

---

## 7·septies. Cambios aplicados en la Fase 2 — paso 27 (análisis de seguridad en cliente + purga de `encryption_utils`)

**Aplicado, sin commitear, verificado sólo en estático** (`py_compile` backend + `npx tsc -b`
frontend en verde; **falta Docker**). Rama `tokens`. Reactiva lo suspendido en F0-3 (C3), ahora
**en cliente**, y purga la última cripto legada del servidor.

### Purga de la cripto legada (`encryption_utils.py`)
El módulo contenía el cifrado v1 del servidor (AES-CFB/ChaCha20 **sin AEAD** → C6; PBKDF2 100k →
A8; capa Fernet → M2) y `decrypt_password`, que hacían al servidor capaz de descifrar (C1). **Todo
eliminado.** Sobrevive sólo `generate_passwords` (CSPRNG `secrets.randbelow`, correcto), que aún
tiene consumidor vivo (`general_views.api_password_generator`) y no es cripto de cifrado. Se
confirmó por grep que **nada** importaba ya las funciones legadas (los helpers Fernet de aquí no los
usa MinIO, que tiene los suyos — M2 se cierra en el paso 28).

### Análisis de seguridad ZERO-KNOWLEDGE (C3 reactivado en cliente)
El servidor **no puede** rehacer el análisis v1 (descifraba la bóveda con `MasterKey.hashed_key`).
Se mueve al navegador:
- **Endpoints retirados**: `/api/security/analysis/` y `/api/security/check-breach/` (v1) se
  **eliminan** de `security_views.py` y `urls.py`. Con ellos se borran las funciones puras de
  Python (`calculate_password_entropy`, `check_password_breach_sync`, `analyze_password_patterns`,
  …) que se habían conservado en el 26 «para reutilizar»: su lógica se **portó a TypeScript**.
- **Análisis en cliente** ([passwordAnalysis.ts](frontend/src/services/passwordAnalysis.ts), puro):
  entropía, categoría de fortaleza, duplicados y patrones, portados 1:1 del Python. La entropía se
  calcula sobre las contraseñas ya descifradas en memoria (`passwordService.getAccounts`, VaultKey
  de `cryptoSession`). [securityService.ts](frontend/src/services/securityService.ts) reescribe
  `getSecurityAnalysis` para construir el mismo `SecurityAnalysisResponse` en local (misma fórmula
  de `overall_score`), así que **`SecurityPage` no cambia**. Se retiró `checkPasswordBreach` (código
  muerto, exigía la maestra).
- **HIBP por proxy k-anonimato** (decisión del usuario): la CSP `connect-src 'self'` impide llamar a
  `api.pwnedpasswords.com` desde el navegador. Nuevo endpoint **`GET /api/security/hibp-range/<prefix>/`**
  ([security_views.py](backend/myapp/views/security_views.py)): recibe **sólo** el prefijo SHA-1 de
  5 hex, relega la range-query a HIBP (`Add-Padding: true`) y devuelve los sufijos; el navegador
  compara en local. El servidor **nunca** ve la contraseña ni el hash completo → **no es oráculo**
  (a diferencia de C3). Sin SSRF (host fijo, prefijo validado a 5 hex). Es un **GET**, así que el
  middleware lo clasifica `normal` (sin el rate limit de la maestra); la CSP queda **intacta**.
- **Metadatos para la antigüedad**: `_serialize_entry` ([password_views.py](backend/myapp/views/password_views.py))
  añade `created_at`/`updated_at` (ISO). Son metadatos no sensibles (cuándo, no qué); el cliente
  calcula `age_days`. `api_security_recommendations` sigue vivo y sólo usa metadatos.

### Residuos declarados del paso 27
- **El análisis exige la bóveda desbloqueada**: sin VaultKey en memoria (o bóveda privada
  bloqueada), esas entradas no se descifran y **quedan fuera** del análisis (no aparecen). No se
  añadió flujo de desbloqueo desde `SecurityPage`: cae en el estado «sin contraseñas» (degradación
  limpia, no rompe). UX para Fase 3.
- **Coste HIBP**: una petición al proxy por prefijo SHA-1 único (deduplicado, concurrencia 6). Para
  bóvedas grandes son varias decenas de peticiones `GET` (sin rate limit). Aceptable para uso
  personal; batching es optimización futura.
- Queda para el **paso 28**: `EncryptedFile.encrypted_file` FileField y la capa Fernet at-rest de
  MinIO (M2).

---

## 7·octies. Hallazgos de la primera verificación en contenedor (25 jul 2026)

Al levantar la pila por primera vez (modo dev: `docker compose down -v && up -d` sin `-f`; BD/MinIO
fresca) se validó lo esperado y aparecieron **dos fallos de integración que la verificación estática
—`py_compile` + `tsc -b`— no puede detectar**: sólo se manifiestan al ejecutar la cripto en el
navegador y al recorrer el flujo de sesión real. Ambos corregidos; **sin commitear**.

### Verificado OK en contenedor
- Migración `0025_purge_legacy_crypto` (purga del paso 26) aplica sobre BD fresca **sin error**; el
  esquema resultante no tiene la tabla `myapp_masterkey` ni los campos v1 purgados.
- Creación de la clave maestra (`setupUserCrypto` → `/api/master-key/setup/`) completa y deja la
  bóveda desbloqueada (tras el fix nº1).

### Fallo de runtime nº1 — AES-GCM `additionalData: undefined` ✅ corregido (CONFIRMADO)
`crypto.ts::aesGcmEncrypt`/`aesGcmDecrypt` incluían **siempre** la clave `additionalData` en los
`AesGcmParams`. En las rutas sin AAD (`wrapVaultKey`/`unwrapVaultKey`: creación de la maestra y
desbloqueo) llegaba `additionalData: undefined`, y el motor del navegador lo rechaza con
*"Failed to execute 'encrypt' on 'SubtleCrypto': AeadParams: additionalData: Not a BufferSource"*
(el WebCrypto de Node sí lo tolera — de ahí que el estático no lo viera). **Fix:** construir el
objeto de params e incluir `additionalData` **sólo cuando hay AAD**. Round-trip AEAD (con y sin AAD,
y rechazo con AAD equivocada) validado. **Confirmado por el usuario**: crear la clave maestra funciona.

### Fallo de runtime nº2 — faltaba el flujo de DESBLOQUEO ✅ corregido (CONFIRMADO)
Bug de integración de la Fase 2: la app tenía flujo de **crear** clave maestra pero **no de
desbloquear**. En zero-knowledge la VaultKey vive **sólo en memoria** (`cryptoSession`); tras login o
recarga se pierde y hay que reintroducir la maestra para re-derivarla. `AuthProvider` se limitaba a
ocultar el modal cuando `hasMasterKey=true` y **nunca** llamaba a `verifyMasterKey`, así que la bóveda
quedaba bloqueada indefinidamente y `/accounts/` (y toda página que descifra) se veía vacía. Funcionaba
sólo en la sesión de **creación** (ahí `setMasterKey` desbloquea). Síntoma reportado: la contraseña
recién creada aparecía, y tras recargar o logout→login desaparecía. **Fix (frontend):**
- Nuevo `frontend/src/components/UnlockVaultModal.tsx` (un campo, la maestra existente, *Desbloquear*
  / *Cerrar sesión*).
- `AuthProvider.tsx`: estado `vaultLocked` + método `unlockVault` (→ `masterKeyService.verifyMasterKey`
  → `cryptoSession.unlock`). Se marca bloqueo tras login/recarga/`checkAuth` si la VaultKey no está en
  memoria y al evento `vault:locked` (auto-bloqueo por inactividad, 15 min); se limpia en logout
  (+`masterKeyService.lock()`). Tras `setupMasterKey` la bóveda queda desbloqueada.
- `App.tsx`: renderiza `UnlockVaultModal` cuando `vaultLocked` (y no el de creación), y **oculta las
  rutas mientras la bóveda está bloqueada** para que al desbloquear se monten de nuevo y carguen ya
  descifradas (sin datos rancios).

`npx tsc -b` en verde. Depende del fix nº1 (el desbloqueo usa `aesGcmDecrypt`). **Confirmado en
navegador (25 jul):** al recargar y en logout→login aparece el modal "Desbloquear bóveda"; tras
introducir la maestra se re-deriva la VaultKey en memoria y reaparecen las contraseñas y los
ficheros. Para verlo hay que regenerar el bundle del frontend (`npm run build` o HMR de Vite);
Docker sólo sirve el backend.

> **Lección para la Fase 2/3:** el `tsc -b`/`py_compile` no cubre ni la semántica de WebCrypto en el
> navegador ni los flujos de sesión de extremo a extremo. Antes de dar por buenos los pasos 21–27 hay
> que ejercer en navegador: crear maestra → añadir → recargar → desbloquear → ver; rotación; bóvedas
> privadas; ficheros. Los criterios de §10 siguen pendientes.

---

## 7·nonies. Paso 28 — SSE-S3 de MinIO, retirada de la Fernet at-rest y purga del `FileField` (25 jul 2026)

Último paso de la Fase 2. Aplicado y **verificado de extremo a extremo en navegador** (subir →
listar con nombre descifrado → descargar íntegro → borrar; los objetos se crean y se eliminan en
MinIO, comprobado por el usuario en la consola `:9001`). **Sin commitear.** Cierra **M2**.

### Retirada de la capa Fernet de aplicación (`minio_service.py`) — cierra M2
La v1 aplicaba una "segunda capa" Fernet en el servidor sobre el fichero. Era **redundante**: desde
la Fase 2 el contenido ya llega cifrado en el cliente por chunks (`crypto.ts::encryptFile`, FileKey
propia envuelta en la VaultKey), y el servidor sólo ve un blob opaco. Además esa capa sostenía
**M2**: si `ENCRYPTION_KEY` no estaba fijada, cada proceso generaba una clave Fernet **efímera** y lo
subido quedaba irrecuperable al reiniciar. Se retira entera:
- `upload_file`/`download_file` pasan el blob **tal cual** (sin `encrypt`/`decrypt`).
- Eliminados `system_fernet`, `_get_system_encryption_key`, los métodos muertos
  `upload_file_simple`/`download_file_simple` (sin llamadores) y los metadatos legacy de algoritmo.
- La env `ENCRYPTION_KEY` queda **huérfana** y se retira de `.env.example` (settings sólo usa
  `SESSION_ENCRYPTION_KEY`, que es otra clave, de cifrado de sesión).

### Cifrado at-rest por SSE-S3 con KMS local de MinIO (sin nube ni coste)
El at-rest lo aporta ahora la **infraestructura**, no un proceso Django:
- `docker-compose.yml`: el servidor MinIO recibe `MINIO_KMS_SECRET_KEY` (formato
  `<nombre>:<32 bytes base64>`, `openssl rand -base64 32`), con guard `:?` **requerido** —coherente
  con las credenciales root—. Es el **KMS integrado** de MinIO: local, gratuito, sin KES ni AWS/Vault.
- `minio_service.upload_file` sube con `sse=SseS3()` → cabecera `X-Amz-Server-Side-Encryption: AES256`;
  MinIO cifra el objeto con esa clave. La descarga la deshace de forma transparente.
- `.env.example` documenta la generación. Verificado: minio-py 7.2.0 expone `SseS3`.

> **Defensa en profundidad, honesta.** Como el contenido ya es ciphertext de cliente (zero-knowledge),
> la SSE **no** aporta confidencialidad primaria; su valor real frente a Fernet es que la clave la
> gestiona la infra en vez de morir con el proceso (cierre efectivo de M2, no por parche).

### Purga del residuo `EncryptedFile.encrypted_file` (FileField)
Migración **`0026_drop_encrypted_file_field`** (a mano, dep. `0025`, destructiva como 0022–0025),
**aplicada OK en contenedor**: `RemoveField` del `FileField` local legado, ya sin ningún flujo v2 que
lo lea o escriba (en v2 el objeto vive en MinIO, `file_path`). Campo quitado del modelo;
`makemigrations --check` → sin cambios pendientes.

### Limpieza de UI muerta en ficheros (residuo de M7 adelantado)
El flujo de ficheros seguía arrastrando de la v1 una **contraseña maestra que ya no se usa** y un
**selector de algoritmo falso**. En zero-knowledge la subida/descarga usan la VaultKey en memoria; el
`fileService` ignoraba esos valores (params `_masterPassword`). Se limpió:
- `UploadFileModal.tsx`: fuera el campo "Contraseña Maestra" (que además era `required`, bloqueando la
  subida) y el selector AES/ChaCha20/Blowfish (todo es AES-256-GCM); texto "10MB" → "100MB".
- `DownloadFileModal.tsx`/`DeleteFileModal.tsx`: sin contraseña, quedan como confirmación simple y
  confirmación destructiva; sus errores ya no dicen "contraseña maestra incorrecta".
- `useFiles.ts`/`FilesPages.tsx`/`fileService.ts`: retirado el hilo `masterPassword`/`algorithm`; el
  sort "Algoritmo" pasa a "Tipo" (ordena por `contentType`). `tsc -b` verde; bundle reconstruido.

### Ficheros tocados
Backend: `minio_service.py`, `models.py`, `migrations/0026_drop_encrypted_file_field.py` (nuevo),
`docker-compose.yml`, `.env.example`. Frontend: `components/files/{UploadFileModal,DownloadFileModal,
DeleteFileModal}.tsx`, `components/hooks/useFiles.ts`, `pages/FilesPages.tsx`, `services/fileService.ts`.

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

> **Estado (25 jul 2026).** Pasos **21–24 (+24b) ✅ APLICADOS** (§7·quater), **paso 25 ✅ APLICADO**
> (§7·quinquies), **paso 26 ✅ APLICADO** (purga del legado, §7·sexies), **paso 27 ✅ APLICADO**
> (análisis de seguridad en cliente + purga de `encryption_utils`, §7·septies) y **paso 28 ✅ APLICADO**
> (SSE-S3 de MinIO + retirada de la Fernet at-rest + purga del `FileField` legado, §7·nonies) — todo
> sin commitear. **Fase 2 COMPLETA.** Verificación en contenedor y navegador iniciada (§7·octies:
> desbloqueo confirmado; §7·nonies: flujo de ficheros confirmado). Los pasos de abajo son el plan
> original; se conservan como referencia.

21. ✅ **Nuevos modelos** (migración aditiva, sin tocar los antiguos):
    `UserCrypto(user, kdf_salt, kdf_params, auth_key_hash, wrapped_vault_key, crypto_version)`;
    añadir `crypto_version` y `ciphertext` (blob AEAD) a `PasswordEntry` y `EncryptedFile`.
22. ✅ **Módulo cripto de cliente** (`frontend/src/services/crypto.ts`) con WebCrypto +
    **hash-wasm** (Argon2id; no `argon2-browser`): derivación, envoltura/desenvoltura de
    `VaultKey`, cifrado/descifrado AES-GCM por entrada y cifrado por chunks para ficheros. La
    `VaultKey` vive **sólo en memoria** (`cryptoSession`), nunca en `localStorage`, con
    auto-bloqueo por inactividad.
23. ✅ **Reescribir los endpoints** para que operen sobre blobs opacos (`password_views.py`,
    `masterkey_views.py`; los de ficheros se completan con el paso 28). Eliminados
    `/api/unlock-password/` y `/api/unlock-all-accounts/`. `decrypt_password`/`decrypt_file_data`
    quedan como código muerto hasta la purga del paso 27.
24. ✅ **Contraseñas de bóveda privada** (+24b): `VaultSubKey` derivada de la contraseña del vault
    y envuelta como la principal; `vault_already_unlocked` **eliminado**; gate por **marcador de
    desbloqueo en servidor** (fail-closed). 24b: `convert-privacy` con re-cifrado en lote. **(A9)**
25. ✅ **Rotación de la clave maestra** re-envolviendo `wrapped_vault_key` en el cliente:
    `change_master_key` verifica con `guard_auth_key` y reemplaza `UserCrypto`;
    `masterKeyService.changeMasterKey` cableado. De paso, `api_delete_vault` migrado a auth
    zero-knowledge + re-cifrado (residuo de §7·quater). **(M8)** — detalle en §7·quinquies.
26. ✅ **Migración de datos / purga del legado** (§7·sexies): migración `0025` DESTRUCTIVA que borra
    el modelo `MasterKey` y todos los campos v1 de `PasswordEntry`/`EncryptedFile`/`Vault`; limpiadas
    todas sus referencias (incl. el bloqueante de import en `forms.py` y el código muerto de
    `security_views`). **Sin asistente de export/reimport**: no hay registros v1 (BD vacía, ruptura
    aceptada); cualquier bóveda v1 previa debe considerarse comprometida.
27. ✅ **Análisis de seguridad en cliente + purga de `encryption_utils`** (§7·septies): entropía/
    duplicados/patrones portados a TS sobre las contraseñas descifradas en memoria; HIBP vía proxy
    k-anonimato `GET /api/security/hibp-range/<prefix>/` (CSP intacta, no es oráculo); endpoints v1
    `/analysis/` y `/check-breach/` retirados. `encryption_utils` reducido a `generate_passwords`.
    **Reactiva lo suspendido en F0-3.**
28. ✅ **Cifrado en reposo de MinIO (SSE-S3) y retirada de la capa Fernet de aplicación** (§7·nonies):
    KMS local de MinIO (`MINIO_KMS_SECRET_KEY`, `sse=SseS3()`); `minio_service` sin Fernet; migración
    `0026` que purga el `FileField` legado `EncryptedFile.encrypted_file`; y limpieza de la contraseña
    maestra/algoritmo muertos en los modales de ficheros. **(M2)**

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
