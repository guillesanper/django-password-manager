# Fijado por digest y con Flask en versión exacta (N11). Antes era `pip install flask`: cada
# build instalaba lo último que hubiera en PyPI.
FROM python:3.12-slim@sha256:cb33f7f771ecec2ef1225cf39b159591a040391bd73e4c01f00fdfc4c47611d2

WORKDIR /app
RUN pip install --no-cache-dir flask==3.1.3
COPY app.py .
CMD ["python", "app.py"]
