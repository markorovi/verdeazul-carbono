# Servicio de bitácora de Verdeazul Carbono (bitacora_svc).
# Se construye desde la raíz del repositorio (contexto "."), en el despliegue:
#   docker build -f deploy/bitacora/Dockerfile -t <registro>/verdeazul/bitacora:vX.Y.Z .
# Solo lleva el servicio y sus dependencias: nada del negocio (sin Django, ORM ni sesiones).
FROM python:3.15-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

# Usuario sin privilegios.
RUN groupadd --gid 10001 bitacora \
    && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin bitacora

WORKDIR /app

COPY bitacora_svc/requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY --chown=10001:10001 bitacora_svc/ bitacora_svc/

USER 10001:10001

# Cloud Run entrega el tráfico en el puerto 8080. El servicio es privado: solo la cuenta de servicio
# de la aplicación tiene roles/run.invoker. Las llaves llegan por variables de entorno desde Secret
# Manager (BITACORA_SALT, BITACORA_SIGNING_KEY, BITACORA_DATABASE_URL) y los puntos van a un bucket
# con retención bloqueada (BITACORA_WORM=gcs, BITACORA_WORM_DESTINO=<bucket>).
EXPOSE 8080

# Un proceso con hilos: el pool de conexiones y el estado del almacén quedan en un solo proceso;
# la cadena se serializa igual en la base con pg_advisory_xact_lock.
CMD ["sh", "-c", "exec gunicorn bitacora_svc.app:aplicacion --bind 0.0.0.0:${PORT:-8080} --workers 1 --threads 8"]
