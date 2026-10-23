# Imágenes fijadas por digest (N11): un tag como `latest` o `3.12-slim` puede pasar a apuntar a
# otra imagen sin que cambie una línea del repo, y el siguiente build la usaría. El tag se deja
# delante del digest para que se lea qué versión es; el que manda es el digest.
FROM python:3.12-slim-bookworm@sha256:6a0e06f5ba0b373d051aabd3fffb9b873f27f9a2a3a14bcbe37dee6f0e3bbc70 AS build

# Las herramientas de compilación sólo viven en esta etapa: la imagen final no lleva compilador.
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libffi-dev \
    libssl-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

COPY --from=ghcr.io/astral-sh/uv:0.13.5@sha256:32a7bb39b496babbd997b0a39a4d66c126bdaf5661b302bf6f06abda8deca6ff /uv /bin/

# Venv con pip (`--seed`): el plan de pruebas instala requirements-dev.txt dentro de `web` con
# `docker compose exec web pip install`, y sin pip en el venv iría al Python del sistema.
COPY requirements.txt .
RUN uv venv --seed /opt/venv \
    && uv pip install --python /opt/venv/bin/python -r requirements.txt


FROM python:3.12-slim-bookworm@sha256:6a0e06f5ba0b373d051aabd3fffb9b873f27f9a2a3a14bcbe37dee6f0e3bbc70

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH=/opt/venv/bin:$PATH

WORKDIR /usr/src/app

# Usuario sin privilegios con el que corre la aplicación (ver docker-entrypoint.sh).
RUN groupadd --system --gid 10001 app \
    && useradd --system --uid 10001 --gid app --no-create-home app

COPY --from=build /opt/venv /opt/venv

COPY . .

# Crear todos los directorios necesarios.
# infrastructure/logs/django es imprescindible: LOGGING usa rutas relativas y
# RotatingFileHandler no crea el directorio — sin él Django no arranca. Antes
# existía sólo de rebote, por el volumen `.:/usr/src/app`, que ya no está.
#
# El código queda de root y `app` sólo puede escribir donde hace falta: collectstatic en
# collected_static y los logs.
RUN mkdir -p /usr/src/app/staticfiles \
    && mkdir -p /usr/src/app/static/dist \
    && mkdir -p /usr/src/app/collected_static \
    && mkdir -p /usr/src/app/infrastructure/logs/django \
    && chown app:app /usr/src/app/collected_static /usr/src/app/infrastructure/logs/django

COPY docker-entrypoint.sh /usr/local/bin/
ENTRYPOINT ["docker-entrypoint.sh"]

EXPOSE 8000

# gunicorn, no runserver (runserver es monohilo, sin límites y no es apto para
# producción). --timeout 120 porque descargar y descifrar dos veces un fichero
# grande supera los 30 s por defecto.
CMD ["gunicorn", "demo.wsgi:application", \
     "--bind", "0.0.0.0:8000", \
     "--workers", "3", \
     "--timeout", "120", \
     "--graceful-timeout", "30", \
     "--max-requests", "1000", \
     "--max-requests-jitter", "100", \
     "--access-logfile", "-", \
     "--error-logfile", "-"]
