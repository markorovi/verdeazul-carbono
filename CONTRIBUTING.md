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

Mediciones, certificados y enmiendas (reglas H1 y H3, inmutabilidad y RLS), con el mismo entorno:

```powershell
. .\scripts\entorno_dev.ps1 -Pruebas
python scripts/probar_mediciones.py
```

Las tablas de mediciones son inmutables (la base rechaza DELETE y TRUNCATE, y las versiones y aprobaciones tampoco admiten UPDATE), así que nada que se confirme ahí se puede limpiar después. Las pruebas nunca confirman datos: cada una corre en una transacción que se revierte y al final se comparan los conteos con los iniciales.

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

## Firma de certificados

- Los certificados se firman con Ed25519. La clave es una semilla de 32 bytes en base64 estándar en la variable `CERT_SIGNING_KEY`.
- En desarrollo la carga `entorno_dev.ps1` desde el secreto `DEV_CERT_SIGNING_KEY`, junto con las demás variables. **Nunca** se versiona, se imprime ni se pega en chats o capturas.
- La huella pública (SHA-256 de la clave pública) se obtiene sin sesión en `GET /certificados/clave-publica/` (campo `huella_sha256`). Es la que se usa como huella confiable.
- Cualquiera puede verificar un certificado sin el proyecto, con `cryptography` instalado:

  ```powershell
  python scripts\verify_cert.py certificado.json --huella <huella_sha256>
  ```

  Códigos de salida: `0` válido, `1` firma inválida, `2` clave no confiable, `3` formato inválido, `4` firma coherente pero sin `--huella` (integridad verificada, origen no).
- También están `/verificar/` (formulario) y `POST /api/verificar/` (JSON, hasta 65536 bytes).
- Pruebas: `python scripts/probar_firma.py` con `. .\scripts\entorno_dev.ps1 -Pruebas`.
- La clave de producción se crea y se rota fuera de Claude Code, solo por el dueño del proyecto.

## Servicios de mediciones

`mediciones/servicios.py` concentra las escrituras del dominio de mediciones (O1 a O4): funciones Python transaccionales, sin vistas ni plantillas.

### Frontera entre servicios y autorización

- Los servicios hacen cumplir, como defensa en profundidad, las condiciones que dependen del estado y del historial: Cd5, Cd6, Cd7, Cd8, Cd10, Cd11, Cd12, Cd19 y Cd20.
- La capa de autorización decide **quién** puede invocar cada servicio: roles y vínculos (Cd1, Cd2, Cd22), ventana de auditoría (Cd3), segundo factor (Cd4), umbrales de lectura (Cd9), proyección (Cd16) y registro de lecturas (Cd17). Los servicios no lo repiten.
- Los disparadores y la RLS de la base repiten las reglas críticas. Si la base rechaza algo con una condición conocida, el servicio lo convierte en `ReglaIncumplida`.

### Servicios y condiciones

| Servicio | Condiciones |
| --- | --- |
| `registrar_medicion` | Cd5: período abierto. Crea la medición en borrador y su versión 1. |
| `modificar_medicion` | Cd6: medición propia y en borrador. Cd5: período abierto. Crea una versión nueva. |
| `presentar_medicion` | Cd6 y Cd5, igual que modificar. Devuelve la huella presentada. |
| `aprobar_medicion` | Cd10: sin certificado vigente. Cd7: período cerrado, medición presentada y `huella_revisada` igual a la vigente. Cd8: el actor no es autor ni quien devolvió, ni aprobó antes en el ciclo. Emite el certificado en la misma transacción al completar las aprobaciones (una, o dos si el volumen supera `valto_tco2e`). |
| `devolver_medicion` | Cd7 y Cd8, igual que aprobar. |
| `reasignar_verificacion` | Cd19: medición presentada, período cerrado, destino con R2 vigente, y verificador asignado impedido por Cd8 o plazo de verificación vencido. Cd8: el destino no puede ser autor. |
| `abrir_periodo`, `cerrar_periodo` | Cd5: solo se cierra un período abierto. La base exige R7. |
| `anular_certificado` | Cd20: certificado vigente, justificación de 10 caracteres o más y anulador que no aprobó la versión. Registra un aviso prioritario a la gerencia en la misma transacción; si el aviso falla, no hay anulación. |
| `exportar_certificado` | Devuelve el documento firmado y la trazabilidad con seudónimos, en JSON canónico, y su SHA-256. |
| `solicitar_enmienda` | Cd11: período cerrado; a lo sumo `tenm_dias` desde el cierre, o un certificado anulado sin otro vigente; el solicitante registró, aprobó o devolvió la medición; justificación. |
| `resolver_enmienda` | Cd12: autorizador distinto del solicitante, del registrante y de todo aprobador. Para autorizar, el plazo se cuenta hasta la fecha de la solicitud. |

### Uso

Cada servicio recibe el actor (`Usuario`) como primer argumento. Abre su propia transacción y declara al actor con `como_actor`, así que quien llama no lo hace. Si algo falla, no queda ningún cambio.

```python
from mediciones import servicios
from mediciones.errores import NoEncontrado, ReglaIncumplida

try:
    resultado = servicios.aprobar_medicion(actor, medicion_id, huella_revisada=huella)
except ReglaIncumplida as error:
    # error.condicion ("Cd7", "Cd8", ...) es estable; error.motivo es una frase sin datos sensibles.
    ...
except NoEncontrado:
    # No existe o la RLS no la deja ver: no se distingue un caso del otro.
    ...
```

- Decida por `error.condicion`, no por el texto de `error.motivo`.
- `ParametroNoConfigurado` indica que falta un parámetro de política. El servicio falla cerrado y no usa valores por defecto.
- Cualquier otro error de base, por ejemplo un permiso de RLS, se propaga tal cual.
- Los servicios devuelven dataclasses simples. Nunca devuelven querysets ni datos de otras personas.

### Plazos y parámetros

Se leen de `PoliticaParametro`; nunca se escriben en el código.

| Clave | Uso | Estado |
| --- | --- | --- |
| `valto_tco2e` | Volumen alto | Sembrada |
| `tenm_dias` | Plazo de enmienda | Sembrada |
| `tver_dias_habiles` | Plazo de verificación (Cd19) | Sembrada (0008) |

Si faltara un parámetro, el servicio falla cerrado con `ParametroNoConfigurado`.

- Los días hábiles van de lunes a viernes, sobre fechas UTC y sin feriados.
- La hora de los plazos sale de `now()` de la base (`servicios._ahora`). La fecha de emisión del certificado también usa `now()`, pero no depende de esa función.

### Pruebas

Con el entorno de pruebas cargado:

```powershell
. .\scripts\entorno_dev.ps1 -Pruebas
python scripts/probar_servicios.py
```

Corre como `app_rw`. Las dos pruebas que necesitan un cierre en el pasado corren como `migrador`, dentro de la transacción revertida. Termina comparando los conteos con los iniciales.

## Servicios de catálogo y alertas

`catalogo/servicios.py` (O5) y `mediciones/alertas.py` (O8.Rs) siguen el mismo patrón que los servicios de mediciones:

- el actor va primero;
- cada servicio es una transacción con `como_actor`;
- cada violación lanza `ReglaIncumplida`, sin dejar cambios.

El rol del actor lo decide la autorización. El rol de la cuenta **destino** (R1 para un técnico, R6 para un propietario) sí lo comprueba el servicio, porque es un dato de la cuenta afectada.

### Servicios y condiciones

| Servicio | Condiciones |
| --- | --- |
| `crear_finca` | Uno o varios propietarios (PROPIEDAD). Cd14: todos con R6 vigente y ninguno es el actor. Un aviso por propietario. |
| `crear_parcela` | Finca activa (VIGENCIA). Cd14: el actor no es propietario de la finca. Sin traslape (UNIDAD) y con polígono válido (GEOMETRIA). Código único en la finca (CODIGO). Un aviso por propietario. |
| `cambiar_propietarios` | Cd14: nadie se agrega a sí mismo y todo agregado tiene R6. Cd15: sin mediciones en curso en la finca. La finca conserva al menos un propietario (PROPIEDAD). Un aviso por cuenta agregada o retirada. Los certificados vigentes no lo impiden y no cambian. |
| `modificar_parcela` | Cd15: sin mediciones en curso; si cambian los límites, tampoco certificado vigente. Sin traslape (UNIDAD). |
| `asignar_tecnico` | Cd14: el destino es otra persona, tiene R1 vigente y el vencimiento es futuro. Avisa al técnico asignado. Una cobertura temporal es otra asignación con vencimiento. |
| `dar_de_baja_parcela` | Cd15: sin mediciones en curso ni certificado vigente. Baja lógica: no hay borrado físico y `app_rw` no tiene DELETE. |
| `resolver_alerta` | Cd18: alerta pendiente, justificación de 10 caracteres o más, y el actor no es parte. Partes: quien originó el evento (`usuario`) y la cuenta afectada (`cuenta_afectada`). |

- **Mediciones en curso:** `borrador`, `presentada`, `devuelta` o `aprobada`.
- **Certificado vigente:** se reconoce por el estado `certificada`, que la base mantiene solo mientras el certificado está vigente.
- **Lectura para Cd15:** el administrador de catálogo (R3) no tiene rol de lectura de mediciones. Por eso el servicio declara `app.proposito = 'catalogo'` solo durante esa consulta. La política `medicion_estado_para_catalogo` deja ver entonces el estado de las mediciones, y nada más: ni versiones, ni aprobaciones, ni certificados.

### Avisos

- `mediciones.alertas.registrar_aviso` es el único punto de registro de avisos, incluido el aviso de anulación de certificados.
- **Falla cerrado:** el aviso se registra en la misma transacción que la operación; si no se puede registrar, la operación no ocurre.
- **Tipos:** `alta_finca`, `alta_parcela`, `cambio_propietarios`, `asignacion_tecnico` y `anulacion_certificado`.
- **Prioridad:** es `prioritaria` cuando quien opera dio de alta la cuenta afectada (`usuarios_usuario.creado_por`). En los demás casos es `aviso`, y también mientras `creado_por` esté vacío.
- **Defensa en la base:** la restricción `alerta_resolucion_independiente` repite Cd18: quien resuelve no puede ser parte de la alerta. La justificación mínima la exige el servicio.

### Parámetros sembrados

| Clave | Valor | Uso |
| --- | --- | --- |
| `valto_tco2e` | 500 | Volumen alto (t CO2e) |
| `tenm_dias` | 90 | Plazo de enmienda (días) |
| `tver_dias_habiles` | 15 | Plazo de verificación (días hábiles) |
| `waud_dias_anuales` | 30 | Ventana del auditor (días por año) |
| `temg_horas` | 4 | Vigencia máxima del acceso de emergencia |
| `trev_emg_horas` | 24 | Revisión del acceso de emergencia |

También siguen sembrados `wc_horas`, `wl_dias` y los `h2_*` de la regla H2.

### Pruebas

```powershell
. .\scripts\entorno_dev.ps1 -Pruebas
python scripts/probar_catalogo.py
```

## Producción

- El corte y las migraciones de producción los hace **solo el dueño del proyecto**, con `scripts/entorno_prod.ps1` (modos `-Migrador` y `-App`) y `scripts/reporte_bd.py`. `entorno_prod.ps1` y `configurar_bd.py --entorno prod` exigen escribir `PRODUCCION`.
- Nunca se ejecutan desde Claude Code ni desde otra herramienta automática.
- `python scripts/reporte_bd.py` revisa en modo de solo lectura la configuración de la base a la que apunte `DATABASE_URL` (dev o producción): roles, CONNECT de PUBLIC, esquema, RLS, disparadores, funciones, privilegios de `app_rw` y migraciones. Termina con código 1 si encuentra un `[FALLO]`.

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
