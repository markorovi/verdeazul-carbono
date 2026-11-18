# Aplicación Verdeazul Carbono (Django + gunicorn).
# Se construye desde la raíz del repositorio:
#   docker build -t <registro>/verdeazul/app:vX.Y.Z .
# Imagen base con versión explícita y digest (nunca latest). Python 3.13.7: la misma versión con la
# que corren las pruebas. Dependabot propone las actualizaciones de etiqueta y digest.
FROM python:3.15.2-slim-trixie@sha256:65a65fc7b30b06cb6df4930fd4650697cb23f4c2698ab81fc87e4b031bc36928

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Usuario sin privilegios.
RUN groupadd --gid 10001 appuser \
    && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin appuser

WORKDIR /app

# Solo las dependencias de ejecución; las de desarrollo (requirements-dev.txt) no entran.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# .dockerignore excluye .git, .venv, .env*, credenciales, .opa_local.json, scripts/ y la documentación local.
COPY --chown=10001:10001 . .

USER 10001:10001

# Cloud Run entrega el tráfico en el puerto de la variable PORT (8080 por defecto).
EXPOSE 8080

CMD ["sh", "-c", "exec gunicorn config.wsgi:application --bind 0.0.0.0:${PORT:-8080} --workers 2 --threads 4 --timeout 60"]
