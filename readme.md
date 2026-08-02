# Gestor de Contraseñas

Gestor de contraseñas web con arquitectura *zero-knowledge*: el cifrado y descifrado
de las bóvedas ocurre **en el navegador**, de modo que el servidor nunca ve las
contraseñas ni los ficheros en claro. Backend en Django + DRF, frontend en
React + Vite, y todo el entorno orquestado con Docker Compose.

## Arquitectura

Todo se levanta con un único `docker compose` desde `backend/`. Los servicios son:

| Servicio | Imagen | Para qué |
|---|---|---|
| `web` | Django (build local) | API y aplicación (gunicorn) |
| `db` | postgres:17 | Base de datos |
| `redis` | redis:7.2 | Caché, sesiones y *rate limiting* |
| `minio` | minio | Almacén S3 de ficheros cifrados (cifrado at-rest SSE-S3) |
| `nginx` | nginx:1.25 | Proxy TLS; **única** puerta de entrada desde fuera (80/443) |
| `prometheus` | prometheus | Métricas |
| `grafana` | grafana | Paneles de métricas |
| `webhook-collector` | build local | Auditoría |

El **frontend** (React/Vite) **no** es un servicio de Docker: se compila en el host y
el resultado (`backend/static/dist/`) se copia dentro de la imagen `web`. Hay que
compilarlo **antes** de construir la imagen.

## Requisitos previos

- **Docker** y **Docker Compose v2** (`docker compose`, no `docker-compose`).
- **Node.js 20+** y **pnpm** (para compilar el frontend). Instalar pnpm: `npm install -g pnpm`.
- **OpenSSL** (para generar el certificado TLS de desarrollo).
- **Python 3.12** *(opcional)*: solo para generar algunos secretos con los comandos de
  abajo. Si no lo tienes a mano, puedes generarlos en cualquier máquina con Python o
  dentro de la imagen `web` una vez construida.

## Puesta en marcha

Todos los comandos de Docker se ejecutan **desde `backend/`** (ahí viven los
`docker-compose.yml`).

### 1. Clonar el repositorio

```bash
git clone https://github.com/guillesanper/django-password-manager.git
cd django-password-manager
```

### 2. Crear y rellenar `backend/.env`

Los secretos **no** están versionados. Copia la plantilla y rellena cada valor:

```bash
cp backend/.env.example backend/.env
```

`backend/.env.example` documenta variable por variable. Los secretos **imprescindibles**
(sin valor por defecto: el arranque falla si faltan) son:

| Variable | Qué es | Cómo generarla |
|---|---|---|
| `DJANGO_SECRET_KEY` | Clave de firma de Django/JWT | `python -c "from django.core.management.utils import get_random_secret_key as g; print(g())"` |
| `SESSION_ENCRYPTION_KEY` | Clave Fernet para el cifrado de sesión | `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"` |
| `POSTGRES_PASSWORD` | Contraseña de Postgres | `python -c "import secrets; print(secrets.token_urlsafe(32))"` |
| `REDIS_PASSWORD` | Contraseña de Redis | `python -c "import secrets; print(secrets.token_urlsafe(32))"` |
| `MINIO_ROOT_USER` / `MINIO_ROOT_PASSWORD` | Credenciales root de MinIO | cualquier usuario/contraseña fuertes |
| `MINIO_ACCESS_KEY` / `MINIO_SECRET_KEY` | Credenciales que usa Django contra MinIO | pueden coincidir con las root |
| `MINIO_KMS_SECRET_KEY` | Clave del KMS integrado (SSE-S3) | `echo "minio-default-key:$(openssl rand -base64 32)"` |
| `GRAFANA_ADMIN_PASSWORD` | Contraseña de admin de Grafana | cualquier contraseña fuerte |

> ⚠️ **Redis**: además de `REDIS_PASSWORD`, las variables `REDIS_URL` y
> `REDIS_SESSIONS_URL` deben incluir esa misma contraseña
> (`redis://:<REDIS_PASSWORD>@redis:6379/1`).

El resto de variables (`POSTGRES_DB`, `POSTGRES_USER`, `DJANGO_ALLOWED_HOSTS`,
`CORS_ALLOWED_ORIGINS`, `DJANGO_TRUSTED_PROXIES`, TLS/HSTS…) traen valores válidos
para ejecutar en local; léelas en `backend/.env.example` antes de tocarlas.

### 3. Generar el certificado TLS de nginx

La configuración base sirve **HTTPS**, y nginx **no arranca** sin certificado. En local
se autofirma (el navegador avisará de certificado no fiable en la primera visita; es
esperado):

```bash
cd backend/infrastructure/nginx/ssl

openssl req -x509 -nodes -newkey rsa:2048 -days 825 \
  -keyout privkey.pem -out fullchain.pem \
  -subj "/C=ES/O=Gestor de Contrasenas (dev)/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,DNS:web,IP:127.0.0.1" \
  -addext "keyUsage=digitalSignature,keyEncipherment" \
  -addext "extendedKeyUsage=serverAuth"

cd -
```

> En Git Bash sobre Windows, antepón `MSYS_NO_PATHCONV=1` al comando `openssl`, o el
> `-subj` se interpreta como una ruta de Windows. Más detalles y el flujo de producción
> (Let's Encrypt) en `backend/infrastructure/nginx/ssl/README.md`.

### 4. Compilar el frontend

Se compila en el host; la salida va a `backend/static/dist/`, que el `Dockerfile` copia
a la imagen. **Hay que hacerlo antes de construir `web`.**

```bash
cd frontend
pnpm install
pnpm build
cd ..
```

### 5. Levantar Docker

```bash
cd backend
docker compose up -d --build
```

Al arrancar, `web` aplica migraciones, hace `collectstatic` y crea los buckets de MinIO
automáticamente. Comprueba el estado con `docker compose ps` / `docker compose logs -f web`.

### 6. Acceder

- **Aplicación**: <https://localhost> (acepta el aviso del certificado autofirmado)
- **Consola de MinIO**: <http://localhost:9001>
- **Grafana**: <http://localhost:3000>
- **Prometheus**: <http://localhost:9090>

*(Opcional)* Crear un superusuario para el panel `/admin` de Django:

```bash
docker compose exec web python manage.py createsuperuser
```

## Modo desarrollo (opcional)

Para trabajar con recarga en caliente existe `backend/docker-compose.override.yml`, que
Compose aplica automáticamente si está presente. Repone puertos, monta el código como
volumen y usa `runserver` + Vite dev en lugar de gunicorn. **No está versionado**
(`.gitignore`), así que un clon nuevo solo trae la configuración base (producción local).

Si lo tienes, el flujo de desarrollo es:

```bash
# Terminal 1 — Vite en caliente
cd frontend && pnpm dev            # http://localhost:5174

# Terminal 2 — backend con recarga
cd backend && docker compose up    # http://localhost:8000
```

En ese modo pon `DJANGO_VITE_DEV_MODE=true` en `backend/.env` para que Django cargue los
assets desde el servidor de Vite en vez de los compilados.

## Comandos útiles

Desde `backend/`:

```bash
docker compose ps                       # estado de los servicios
docker compose logs -f web              # logs de la app
docker compose down                     # parar (conserva los datos)
docker compose down -v                  # parar y BORRAR todos los volúmenes (datos)
docker compose exec web python manage.py <cmd>   # cualquier comando de manage.py
```

> Las contraseñas de Postgres y Grafana solo se aplican al **crear** su volumen. Para
> rotarlas sobre un volumen existente, ver las instrucciones en `backend/.env.example`.

## Tests

- **Backend** (pytest): configuración en `pytest.ini` (raíz) y `backend/pytest.ini`.
- **Frontend** (vitest): `cd frontend && pnpm test`.

El plan de pruebas completo está en `PLAN-DE-PRUEBAS.md`.

## Estructura del proyecto

```
django-password-manager/
├── backend/                 # Django + Docker Compose (todos los servicios)
│   ├── demo/                # Configuración del proyecto Django (settings, wsgi…)
│   ├── myapp/               # Lógica de la aplicación
│   ├── infrastructure/      # nginx, minio, monitoring, webhook-collector, logs
│   ├── docker-compose.yml   # Configuración base (producción local)
│   ├── Dockerfile
│   └── .env.example         # Plantilla de secretos
├── frontend/                # SPA React + Vite (se compila a backend/static/dist)
├── AUDITORIA-SEGURIDAD.md   # Auditoría de seguridad
└── PLAN-DE-PRUEBAS.md       # Plan de pruebas
```

## Seguridad

El modelo de amenazas, las decisiones de diseño *zero-knowledge* y el estado de cada
control están documentados en `AUDITORIA-SEGURIDAD.md`.
