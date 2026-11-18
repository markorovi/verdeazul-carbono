# Verdeazul Carbono

Sistema web para registrar fincas, parcelas y mediciones de carbono, verificarlas y emitir certificados firmados. Tiene control de acceso estricto en el servidor y una bitácora a prueba de manipulación.

Es el proyecto del curso CE-1115 Seguridad de la Información (ITCR, grupo 2), Parte 2.

- **Roles y operaciones:** 7 roles (R1 a R7), 8 objetos protegidos y una matriz de 41 operaciones.
- **Autenticación:** Argon2id y TOTP obligatorio.
- **Autorización:** PEP y PIP en la aplicación; el PDP es OPA, con un motor de referencia en Python.
- **Base de datos:** RLS en PostgreSQL y roles con mínimo privilegio.
- **Certificados:** firmados con Ed25519.
- **Bitácora:** servicio aparte, con cadena de hashes y puntos de control firmados.

## Arquitectura

| Componente | Qué es | Dónde corre |
| --- | --- | --- |
| app | Django 5.2 con gunicorn: interfaz, PEP, PIP y servicios de negocio | Cloud Run (público, con TLS gestionado) |
| opa | PDP con la política Rego y los datos de la matriz | Cloud Run privado; solo lo invoca la app con IAM |
| bitacora | Servicio de solo anexar con cadena de hashes y puntos firmados | Cloud Run privado; solo lo invoca la app con IAM |
| Neon (negocio) | PostgreSQL con PostGIS; roles `migrador` y `app_rw` | Neon, proyecto del negocio |
| Neon (bitácora) | PostgreSQL de la bitácora; roles `bit_migrador` y `bit_rw` | Neon, proyecto aparte |
| Secret Manager | Cadenas de conexión, llaves y sales | Google Cloud |
| Cloud Storage | Puntos de control de la bitácora (WORM, retención bloqueada) | Google Cloud |
| Artifact Registry | Imágenes de los tres servicios (repositorio `verdeazul`) | Google Cloud |

## Estructura del repositorio

| Ruta | Contenido |
| --- | --- |
| `config/` | Ajustes, rutas y endurecimiento de errores |
| `usuarios/` | Cuentas, roles, autenticación (Argon2id y TOTP), ventanas, emergencia y recuperación |
| `catalogo/` | Fincas, parcelas (PostGIS por SQL), propiedad y asignaciones |
| `mediciones/` | Períodos, mediciones, aprobaciones, certificados, enmiendas, alertas y firma |
| `autorizacion/` | PEP, PIP, cliente del PDP y de la bitácora, matriz y constantes de política |
| `policy/` | Política Rego y sus pruebas |
| `bitacora_svc/` | Servicio de bitácora (WSGI, sin Django) y su esquema |
| `interfaz/` | Interfaz web: decoradores, registro de operaciones, serializadores y plantillas |
| `deploy/opa/`, `deploy/bitacora/` | Dockerfiles de OPA y de la bitácora (el de la app está en la raíz) |
| `scripts/` | Entornos, configuración de la base, pruebas de extremo a extremo y verificadores |

## Correr y probar en local

Requisitos: Python 3.13 (la versión de las imágenes) y acceso a la rama dev de Neon. En PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
pip install -r requirements-dev.txt        # solo para Bandit

. .\scripts\entorno_dev.ps1                # variables de dev, sin mostrarlas
$env:PDP_BACKEND = 'python'                # o 'opa' con un OPA local (ver CONTRIBUTING.md)
python manage.py runserver 127.0.0.1:8000
```

El servicio de bitácora local se arranca como indica CONTRIBUTING.md (sección Bitácora).

Pruebas:

```powershell
python manage.py test config usuarios mediciones catalogo autorizacion bitacora_svc interfaz
. .\scripts\entorno_dev.ps1 -Pruebas
python scripts/probar_interfaz.py          # y los demás scripts probar_*.py, uno a la vez
python -m bandit -r config usuarios mediciones catalogo autorizacion bitacora_svc interfaz scripts manage.py -x "*/tests.py,*/migrations/*,*/probar_*.py"
python scripts/escanear_secretos.py        # árbol de trabajo y todo el historial
```

Las pruebas contra dev corren en transacciones revertidas y comparan conteos: no dejan datos.

## Reconstruir las imágenes

Las etiquetas siempre son explícitas (`vX.Y.Z`), nunca `latest`. Las imágenes base están fijadas por versión y digest, y Dependabot propone las actualizaciones. Las tres se construyen desde la raíz:

```powershell
$PROYECTO = '<proyecto>'
$REGION = '<region>'
$VERSION = 'vX.Y.Z'
$REGISTRO = "$REGION-docker.pkg.dev/$PROYECTO/verdeazul"

docker build -t "$REGISTRO/app:$VERSION" .
docker build -f deploy/opa/Dockerfile -t "$REGISTRO/opa:$VERSION" .
docker build -f deploy/bitacora/Dockerfile -t "$REGISTRO/bitacora:$VERSION" .
```

Las tres imágenes corren sin root (la app y la bitácora con uid 10001, OPA con 65532) y escuchan en `PORT` (8080). La app usa gunicorn con 2 workers, 4 hilos y timeout de 60 s. `.dockerignore` deja fuera:

- `.git`, `.venv` y los `.env*`;
- credenciales y claves;
- `.opa_local.json`;
- `scripts/` y `requirements-dev.txt`.

## Secretos (por nombre)

Llegan solo por variables de entorno desde Secret Manager. En dev llevan el prefijo `DEV_` y los carga `scripts/entorno_dev.ps1`.

| Secreto | Contenido | Servicio |
| --- | --- | --- |
| `SECRET_KEY` | Clave de Django | app |
| `DATABASE_URL_APP` | Cadena de `app_rw` (variable `DATABASE_URL`) | app |
| `DATABASE_URL_MIGRADOR` | Cadena de `migrador`; solo para migraciones, nunca en Cloud Run | operación (dueño) |
| `CLAVE_TOTP` | Llave AES-256-GCM de los secretos TOTP | app |
| `CERT_SIGNING_KEY` | Semilla Ed25519 de los certificados | app |
| `DATABASE_URL_BITACORA` | Cadena de `bit_rw` (variable `BITACORA_DATABASE_URL`) | bitacora |
| `BITACORA_SALT` | Sal HMAC de los seudónimos | bitacora |
| `BITACORA_SIGNING_KEY` | Semilla Ed25519 de los puntos de control | bitacora |

Cada secreto lo lee solo la cuenta de servicio del servicio que lo usa.

## Variables de despliegue

| Variable | Servicio | Contenido |
| --- | --- | --- |
| `ALLOWED_HOSTS` | app | Hosts separados por comas. **Obligatoria:** sin ella no se atiende ningún host. |
| `CSRF_TRUSTED_ORIGINS` | app | Orígenes extra separados por comas; vacío si no hay dominio propio |
| `TRUSTED_PROXY_COUNT` | app | Proxies delante (1 en Cloud Run); define qué entrada de `X-Forwarded-For` se usa |
| `BITACORA_URL` | app | URL del servicio de bitácora |
| `BITACORA_AUDIENCE` | app | Audiencia del token de identidad para la bitácora privada |
| `PDP_BACKEND` | app | `opa` (por defecto) o `python` |
| `OPA_URL`, `OPA_AUDIENCE` | app | URL del servicio OPA y audiencia de su token |
| `BITACORA_TIMEOUT`, `PDP_TIMEOUT` | app | Segundos, entre 0.1 y 10 (2 por defecto) |
| `LISTA_TAMANO_PAGINA` | app | Filas por página en las listas, entre 1 y 20 (10 por defecto) |
| `BITACORA_ESQUEMA` | bitacora | Esquema de la base (por defecto `bitacora`) |
| `BITACORA_WORM`, `BITACORA_WORM_DESTINO` | bitacora | `gcs` y el bucket con retención bloqueada; sin ellas no arranca |
| `BITACORA_PUNTO_CADA` | bitacora | Eventos entre puntos de control (25 por defecto) |

No se define `ENTORNO` en la nube: sin ella la app asume producción (DEBUG apagado, HTTPS obligatorio, cookies `Secure` y HSTS). `ENTORNO=local` está prohibido en Cloud Run.

## Migraciones

Las aplica solo el dueño del proyecto, como `migrador`:

```powershell
. .\scripts\entorno_prod.ps1 -Migrador     # en dev: . .\scripts\entorno_dev.ps1 -Migrador
python manage.py migrate
python scripts/reporte_bd.py               # revisión de solo lectura de roles, RLS y privilegios
```

El esquema de la base de bitácora se aplica con `scripts/aplicar_esquema_bitacora.py`, con la cuenta propietaria de esa base.

## Comandos operativos

| Comando | Cuándo |
| --- | --- |
| `python manage.py registrar_version_politica` | En cada despliegue: registra en la bitácora la huella de la matriz, las constantes y la política |
| `python manage.py verificar_bitacora` | Periódicamente: el servicio verifica la cadena y los puntos; si falla, alerta a R7 |
| `python scripts/verify_bitacora.py --eventos <archivo.jsonl> --puntos <carpeta> --huella <hex>` | Auditoría independiente de una exportación de la bitácora |
| `python scripts/verificar_certificado.py <certificado.json> --huella <hex>` | Verificación independiente de un certificado |
| `python scripts/escanear_secretos.py` | Antes de publicar: árbol y todo el historial |

Códigos de salida de `verificar_certificado.py`:

| Código | Significado |
| --- | --- |
| 0 | Íntegro y emitido por la clave esperada |
| 1 | Íntegro con otra clave |
| 2 | Alterado |
| 3 | Formato inválido |
| 4 | Íntegro, pero sin `--huella` no se confirma el emisor |

La huella se publica en `/clave-publica/`. El verificador solo usa la biblioteca estándar y `cryptography`.

Tanto el verificador como la página `/verificar/` aceptan el certificado solo o el archivo completo que entrega la exportación (`certificado`, `estado` y `trazabilidad`). Con el archivo completo verifican solo el objeto `certificado` y lo indican en una línea aparte, porque `estado` y `trazabilidad` no están firmados.

## Cuentas de demostración

```powershell
python manage.py sembrar_demo --salida <ruta fuera del repositorio>
python manage.py sembrar_demo --salida <otra ruta> --rotar
```

Qué crea:
- 7 cuentas, una por rol;
- una finca con su dueño R6;
- 3 parcelas, con el técnico R1 asignado a la primera;
- un período abierto.

Cómo se crea:
- La primera cuenta R4 se crea por arranque directo, porque el alta exige un R4, y ese arranque queda registrado en la bitácora. Si la bitácora no lo confirma, no se crea nada.
- Las demás cuentas pasan por los servicios.

El archivo de salida:
- tiene usuario, contraseña, secreto TOTP en base32 y URI otpauth;
- debe quedar fuera del repositorio y no existir de antemano.

La consola solo muestra conteos y la ruta. El comando es idempotente; `--rotar` regenera contraseñas y secretos TOTP.

Para entrar sin una aplicación autenticadora:

```powershell
python scripts/generar_totp.py             # pide el secreto con entrada oculta y muestra el código vigente
```

## Versiones publicadas

| Imagen | Etiqueta | Commit | Estado |
| --- | --- | --- | --- |
