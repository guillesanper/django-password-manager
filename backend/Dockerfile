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

# Crear todos los directorios necesarios
RUN mkdir -p /usr/src/app/staticfiles \
    && mkdir -p /usr/src/app/static/dist \
    && mkdir -p /usr/src/app/collected_static

EXPOSE 8000

CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]