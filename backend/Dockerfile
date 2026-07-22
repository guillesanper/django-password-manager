FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /usr/src/app

# Instalar dependencias del sistema necesarias para cryptography
RUN apt-get update && apt-get install -y \
    curl \
    libpq-dev \
    gcc \
    build-essential \
    libffi-dev \
    libssl-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

COPY requirements.txt .
RUN uv pip install -r requirements.txt --system

COPY . .

# Crear todos los directorios necesarios.
# infrastructure/logs/django es imprescindible: LOGGING usa rutas relativas y
# RotatingFileHandler no crea el directorio — sin él Django no arranca. Antes
# existía sólo de rebote, por el volumen `.:/usr/src/app`, que ya no está.
RUN mkdir -p /usr/src/app/staticfiles \
    && mkdir -p /usr/src/app/static/dist \
    && mkdir -p /usr/src/app/collected_static \
    && mkdir -p /usr/src/app/infrastructure/logs/django

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
