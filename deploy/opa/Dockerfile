# PDP de Verdeazul Carbono: OPA con la política y los datos de autorización.
# Se construye desde la raíz del repositorio (contexto "."), en el despliegue:
#   docker build -f deploy/opa/Dockerfile -t <registro>/verdeazul/opa:vX.Y.Z .
# Variante estática de la imagen oficial, con versión explícita y digest (nunca latest).
FROM openpolicyagent/opa:1.22.4-static@sha256:12cecac5a174368f7d3f09d3a19d040ebe0c91d576e520335ae7a985a26e39d3

# Solo la política y sus datos; las pruebas Rego no viajan en la imagen.
COPY policy/autorizacion.rego /politica/autorizacion.rego
COPY autorizacion/matriz.json /datos/matriz.json
COPY autorizacion/politica.json /datos/politica.json

# Usuario sin privilegios (nonroot de las imágenes distroless/static).
USER 65532:65532

# Cloud Run entrega el tráfico en el puerto 8080. El servicio es privado: solo lo invoca la
# aplicación con un token de identidad (OPA_AUDIENCE). OPA no lleva autenticación propia: la
# aplica IAM de Cloud Run delante (roles/run.invoker solo para la cuenta de la aplicación).
EXPOSE 8080

CMD ["run", "--server", "--addr=0.0.0.0:8080", "--log-level=error", \
     "/politica/autorizacion.rego", \
     "verdeazul.matriz:/datos/matriz.json", \
     "verdeazul.politica:/datos/politica.json"]
