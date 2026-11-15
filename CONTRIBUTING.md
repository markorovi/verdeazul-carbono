# Cómo contribuir

Guía para trabajar en local sin debilitar la seguridad de producción.

## Requisitos

- Git.
- Python 3.12 o superior. Lo ideal es 3.15, la misma versión del contenedor.

## Puesta en marcha local (PowerShell)

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

Defina las variables de entorno **solo para la sesión actual** (desaparecen al cerrar la terminal) y arranque el servidor:

```powershell
$env:ENTORNO = "local"
$env:SECRET_KEY = "clave-local-de-desarrollo"
$env:DATABASE_URL = "sqlite:///local.db"

python manage.py migrate
python manage.py runserver
```

Abra http://127.0.0.1:8000/.

Importante:

- **Nunca** use en local los valores de producción (la `SECRET_KEY` o la `DATABASE_URL` de Secret Manager).
- `ENTORNO=local` desactiva HTTPS obligatorio, cookies `Secure` y HSTS, y activa `DEBUG`. Por eso está **prohibido en Cloud Run**: si se detecta la variable `K_SERVICE`, el código se niega a arrancar.
- Si `ENTORNO` no está definida, se asume `produccion`, con todas las protecciones activas.

## Reglas del equipo

- Trabaje en ramas `feature/<nombre>` y abra un pull request hacia `main`. Otra persona del equipo debe revisarlo antes de fusionarlo.
- Nunca ponga credenciales, archivos `.env` ni claves en el código ni en los chats.
- Antes de cada `git push`, este comando no debe devolver nada:

  ```powershell
  git grep -i "postgresql://"
  ```

- Solo una persona etiqueta versiones (`vX.Y.Z`), construye la imagen y despliega. Así cada imagen corresponde a un commit concreto.
- Cada persona configura su propia identidad en Git:

  ```powershell
  git config user.name "Su Nombre"
  git config user.email "su-correo@ejemplo.com"
  ```

## Defensa individual

Todas las personas del equipo deben poder explicar el sistema completo: el código, el despliegue, la gestión de secretos y las decisiones de seguridad.
