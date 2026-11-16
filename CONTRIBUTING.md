# Cómo contribuir

Guía para trabajar en local sin debilitar la seguridad de producción.

## Requisitos

- Git.
- Python 3.13 o superior. Lo ideal es 3.15, la misma versión del contenedor.

## Puesta en marcha local (PowerShell)

Las migraciones usan SQL propio de PostgreSQL con PostGIS, así que el desarrollo local trabaja contra la rama dev de Neon. No hay modo con SQLite.

Antes de empezar necesita:

- Python 3.13 o superior y un entorno virtual del proyecto.
- Google Cloud SDK (`gcloud`) con sesión iniciada (`gcloud auth login`) y permiso de lectura sobre los secretos `DEV_` del proyecto `verdeazul-p2`. Ese acceso se pide al dueño del proyecto. Si `gcloud` no está en el PATH, los scripts de `scripts/` lo localizan solos.

Instalación:

```powershell
git clone https://github.com/markorovi/verdeazul-carbono
cd verdeazul-carbono
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Si `Activate.ps1` da un error de ejecución de scripts, ejecute una sola vez:

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

### Cargar el entorno

`scripts/entorno_dev.ps1` lee las cadenas de conexión de Secret Manager y las deja como variables de entorno **solo en la sesión actual**, sin mostrarlas. Se ejecuta con un punto al inicio para que las variables queden en la sesión:

| Comando | `DATABASE_URL` | Para qué |
| --- | --- | --- |
| `. .\scripts\entorno_dev.ps1` | rol `app_rw` | ejecutar la aplicación |
| `. .\scripts\entorno_dev.ps1 -Migrador` | rol `migrador` | aplicar migraciones |
| `. .\scripts\entorno_dev.ps1 -Pruebas` | rol `app_rw`, además `DATABASE_URL_APP` y `DATABASE_URL_MIGRADOR` | pruebas de base de datos |

En todos los casos define también `ENTORNO=local`, una `SECRET_KEY` fija de desarrollo, `DATABASE_URL_BITACORA` y `CLAVE_TOTP` (la clave que cifra los secretos TOTP, leída del secreto `DEV_CLAVE_TOTP`). Si algún secreto no se puede leer, no modifica ninguna variable.

Ejecutar la aplicación:

```powershell
. .\scripts\entorno_dev.ps1
python manage.py runserver
```

Abra http://127.0.0.1:8000/.

Aplicar migraciones (solo con `migrador`; `app_rw` no puede crear tablas):

```powershell
. .\scripts\entorno_dev.ps1 -Migrador
python manage.py migrate
```

Después de migrar, vuelva a cargar el entorno sin `-Migrador` antes de ejecutar la aplicación.

### Pruebas

Reglas y permisos de la base de datos (exclusión de roles, traslape de parcelas, períodos, accesos de emergencia y privilegios de `app_rw`):

```powershell
. .\scripts\entorno_dev.ps1 -Pruebas
python scripts/probar_bd.py
```

Debe terminar con todas las pruebas en OK.

Autenticación (contraseña Argon2id y segundo factor TOTP), con el entorno cargado sin switches; corre dentro de una transacción que se revierte, así que no deja cuentas ni sesiones:

```powershell
. .\scripts\entorno_dev.ps1
python scripts/probar_autenticacion.py
```

Filtro de reportes de error, TOTP, cifrado y hasher (no usan la base de datos; basta con tener el entorno cargado):

```powershell
python manage.py test config usuarios
```

Cuentas de prueba: `python manage.py crear_cuentas_prueba` crea una cuenta por rol (R1 a R7) en la base de dev, con correos del dominio `verdeazul.test` (otro dominio con `--dominio`, por ejemplo `--dominio equipo.test`), y muestra **una sola vez** su contraseña y su secreto TOTP. Guárdelos en un gestor de contraseñas; nunca en el repositorio ni en chats. Si las cuentas ya existen, el comando no las modifica.

Las pruebas automáticas crean sus propias cuentas con el dominio `autoprueba.test` y conviven con las cuentas de prueba reales: no las modifican y al terminar dejan los mismos conteos que había al empezar.

Importante:

- La base de dev es **compartida** por todo el equipo. Las pruebas de `scripts/probar_bd.py` corren cada una en una transacción que siempre se revierte, así que no dejan datos; no cree datos de prueba a mano.
- **Nunca** use en local los valores de producción. `entorno_dev.ps1` solo lee los secretos `DEV_`.
- `ENTORNO=local` desactiva HTTPS obligatorio, cookies `Secure` y HSTS, y activa `DEBUG`. Por eso está **prohibido en Cloud Run**: si se detecta la variable `K_SERVICE`, el código se niega a arrancar.
- Con `DEBUG` activo, las páginas de error ocultan cualquier variable cuyo nombre contenga `DATABASE`, `KEY`, `SECRET` o `PASS`; aun así, no comparta capturas de esas páginas.
- Si `ENTORNO` no está definida, se asume `produccion`, con todas las protecciones activas.

## Reglas del equipo

- Trabaje en ramas `feature/<nombre>` y abra un pull request hacia `main`. Otra persona del equipo debe revisarlo antes de fusionarlo.
- Nunca ponga credenciales, archivos `.env` ni claves en el código ni en los chats.
- Antes de cada `git push`, este comando no debe devolver nada:

  ```powershell
  git grep -i -E "postgres(ql)?:[/]{2}"
  ```

- Solo una persona etiqueta versiones (`vX.Y.Z`), construye la imagen y despliega. Así cada imagen corresponde a un commit concreto.
- Cada persona configura su propia identidad en Git:

  ```powershell
  git config user.name "Su Nombre"
  git config user.email "su-correo@ejemplo.com"
  ```

## Defensa individual

Todas las personas del equipo deben poder explicar el sistema completo: el código, el despliegue, la gestión de secretos y las decisiones de seguridad.
