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

## Servicios de cuentas, ventanas, emergencia y recuperación

`usuarios/servicios.py` sigue el patrón de los demás servicios.

- Hace cumplir Cd13 (nadie opera sobre sus propios roles ni sobre su propia cuenta; sin pares de roles excluyentes), Cd23 (ventanas de auditoría) y Cd24 (emergencia).
- El rol del **actor** lo decide la autorización.
- El rol de las **cuentas afectadas** sí lo comprueba el servicio: auditor solo R5, autorizadores R4 y R7, rol suplido R1 o R2.

### Servicios y condiciones

| Servicio | Condiciones |
| --- | --- |
| `alta_cuenta` | Correo único (CUENTA). La cuenta nace con `creado_por` = actor, sin contraseña utilizable y sin roles. Devuelve **una vez** un código de alta. |
| `modificar_cuenta` | Solo el nombre. Roles, credenciales y estado tienen servicios propios, y `app_rw` no puede cambiar el correo. |
| `asignar_rol` | Cd13: el actor no se asigna roles a sí mismo y el rol no forma un par excluyente con los vigentes (ExclusionEstatica, que la base también impone con un disparador). |
| `revocar_rol` | Cd13: el actor no se revoca roles a sí mismo. |
| `dar_de_baja_cuenta` | Cd13: el actor no se da de baja a sí mismo. Baja lógica: cierra las sesiones de la cuenta e invalida sus códigos pendientes. |
| `solicitar_ventana` | Cd23: destino solo R5 y fin posterior al inicio. La solicitud no da acceso. |
| `abrir_ventana` | Cd23: solicitud pendiente de otra persona, destino solo R5 y a lo sumo `waud_dias_anuales` días de ventanas abiertas por año calendario. Se abre una sola vez. |
| `autorizar_emergencia` | Cd24: doble control, explicado abajo. |
| `acceso_emergencia_vigente`, `consumir_emergencia` | Lectura del rol suplido vigente y consumo de un solo uso, para el punto de decisión de acceso. |
| `emitir_recuperacion` | Código de recuperación para otra cuenta con segundo factor. Invalida los pendientes y avisa a R7. |
| `canjear_codigo` | Sin sesión. Explicado abajo. |

**Días de ventana:** se cuenta la duración real (segundos / 86400). Una ventana que cruza el cambio de año suma a cada año solo la parte que cae en él (fechas UTC).

**Doble control de emergencia (`autorizar_emergencia`):**

- La primera autorización (R4 o R7) crea un registro pendiente. La segunda, de otra persona con el rol complementario, lo activa.
- El beneficiario no puede ser autorizador. El rol suplido es R1 o R2, con perfil de solo lectura.
- Vence en `min(temg_horas, 4 h)`; las 4 h son el tope del CHECK `emergencia_duracion_maxima`.
- Es de un solo uso.
- Queda con la revisión pendiente hasta `trev_emg_horas` y registra un aviso prioritario a R7.

### Códigos de un solo uso (`usuarios_codigounuso`)

- **Formato:** 256 bits aleatorios (`secrets.token_urlsafe(32)`). Solo se guarda su SHA-256 y se compara con `hmac.compare_digest`. El código en claro se entrega una vez y no se guarda.
- **Vigencia:** 24 horas para el alta y 30 minutos para la recuperación (`usuarios/codigos.py`).
- **Un solo uso**, con consumo atómico.
- **Intentos:** cada fallo suma un intento a los códigos pendientes de la cuenta. Con 5 intentos el código queda invalidado.
- **Permisos de la base:** `app_rw` tiene SELECT e INSERT, y UPDATE solo sobre `usado_en` e `intentos_fallidos`. Un disparador impide usar un código dos veces o bajar sus intentos.
- **Canje (`canjear_codigo(codigo, correo=..., contrasena=..., codigo_totp=...)`):**
  - **Alta:** fija la contraseña inicial y genera el secreto TOTP, que se devuelve una vez. Se confirma en el primer inicio de sesión.
  - **Recuperación:** exige además un código TOTP vigente de la cuenta y cierra sus sesiones.
  - **Fallas del código o del TOTP:** todas lanzan la misma `ReglaIncumplida("RECUPERACION")`, sin revelar si la cuenta existe.
  - **Contraseña que no cumple la política:** lanza `CONTRASENA` y no consume el código.
- **Contraseñas:** Argon2id y los validadores del proyecto (similitud, mínimo de 12, comunes, numéricas). Se admiten frases largas con espacios y no hay reglas de composición.

### Limitaciones

- **Segundo factor perdido:** no hay recuperación sin TOTP. El procedimiento es dar de baja la cuenta y que R4 dé de alta una nueva, con revisión de R7.
- **Sin canal de correo:** el sistema no envía correos. El código de alta o de recuperación lo entrega el administrador por un canal fuera del sistema. La notificación al titular se cubre con el aviso a R7 y con un aviso visible en el siguiente inicio de sesión, que se construirá con la interfaz.

### Pruebas

```powershell
. .\scripts\entorno_dev.ps1 -Pruebas
python scripts/probar_cuentas.py
```

## Autorización

La capa `autorizacion/` separa el PEP y el PIP (en Django) del PDP (OPA, en un servicio aparte).

- **Matriz:** `autorizacion/matriz.json` es la fuente única, con 41 operaciones, 8 objetos, 7 roles y 60 permisos. La política Rego y el motor de referencia en Python la leen igual.
- **Contrato** de entrada y salida del PDP: `autorizacion/CONTRATO.md`.
- **Orden:** autenticación, RBAC, ABAC, H2 y servicio, con deny-overrides y denegación por defecto.

### Por qué hay dos capas

- **Política (PDP):** decide **quién** puede intentar una operación. Usa roles, vínculos, ventana, segundo factor, H2, proyección y registro de lecturas, a partir de hechos que el PIP calcula y que no llevan datos personales.
- **Servicios:** hacen cumplir las condiciones que dependen del **estado y del historial** dentro de su transacción, con bloqueos. Una política no puede garantizar esas condiciones sin carreras.
- **Comprobación cruzada:** la política devuelve en `condiciones_servicio` las condiciones de servicio que exige la operación. El PEP comprueba que el servicio invocado declare aplicarlas (`autorizacion.pep.servicios()`).

| Capa | Condiciones |
| --- | --- |
| Política (OPA y `autorizacion/motor.py`) | Cd1, Cd2, Cd3, Cd4, Cd9, Cd16, Cd17, Cd21, Cd22, más el perfil de emergencia (lectura de Cd24) |
| Servicio (transaccional) | Cd5, Cd6, Cd7, Cd8, Cd10, Cd11, Cd12, Cd13, Cd14, Cd15, Cd18, Cd19, Cd20, Cd23, Cd24 |

### Fail-closed

- Deniegan:
  - una falla del PIP o del PDP (timeout de 2 s, error HTTP o respuesta fuera del contrato);
  - la bitácora no disponible, en las operaciones con Cd8, Cd10, Cd11, Cd12, Cd17 o Cd20;
  - el registro del intento que falla.
- Excepción: si los contadores de H2 no se pueden calcular, Cd9 falla degradado. Concede las parcelas del vínculo habitual y deniega las ajenas y toda exportación.
- El cliente nunca ve la condición de una denegación (`Denegado.publico()`).

### Selector de backend

| Variable | Valores |
| --- | --- |
| `PDP_BACKEND` | `opa` (por defecto) o `python` (motor de referencia). Nunca se cambia de backend solo ante una falla: se deniega. |
| `OPA_URL` | URL del OPA. En dev, por defecto `http://127.0.0.1:8181`. |
| `OPA_AUDIENCE` | En Cloud Run, la audiencia del servicio privado de OPA. Con ella el cliente agrega un token de identidad (`google-auth`). |
| `BITACORA_CLIENTE` | Ruta a la clase de bitácora. El PEP no arranca sin ella; la implementación real llega con la bitácora. |

### OPA local

El binario no se versiona.

1. Descargue la versión fijada (`v1.22.4`) del release oficial en GitHub: `opa_windows_amd64.exe` y su `.sha256`.
2. Verifique el SHA-256 y guarde el binario fuera del repositorio. Por ejemplo, en `%LOCALAPPDATA%\verdeazul\herramientas\opa\v1.22.4\opa.exe`.
3. Escriba su ruta en `.opa_local.json`, en la raíz del repositorio; ese archivo está ignorado por git:

   ```json
   {"opa": "C:\\ruta\\al\\opa.exe", "version": "v1.22.4"}
   ```

Comprobar y probar la política:

```powershell
$opa = (Get-Content .opa_local.json -Raw -Encoding UTF8 | ConvertFrom-Json).opa
& $opa check --strict policy/
& $opa fmt -l policy/
& $opa test policy/ verdeazul.matriz:autorizacion/matriz.json verdeazul.politica:autorizacion/politica.json
```

Servidor local, si quiere usar `PDP_BACKEND=opa` fuera de las pruebas:

```powershell
& $opa run --server --addr=127.0.0.1:8181 policy/autorizacion.rego verdeazul.matriz:autorizacion/matriz.json verdeazul.politica:autorizacion/politica.json
```

La imagen de despliegue se describe en `deploy/opa/Dockerfile`: `openpolicyagent/opa:1.22.4-static`, sin root y en el puerto 8080.

### Registro de accesos y retención

- `autorizacion_registroacceso` guarda cada intento de lectura y es la fuente de los contadores de H2 y de las alertas por Cd2.
- Es inmutable y tiene RLS: cada actor solo ve e inserta sus propias filas.
- **Retención de 24 meses**, por política. No hay purga automática.

### Pruebas

```powershell
. .\scripts\entorno_dev.ps1 -Pruebas
python manage.py test autorizacion
python scripts/probar_autorizacion.py
```

`probar_autorizacion.py` hace lo siguiente:

1. Arranca un OPA local con el binario de `.opa_local.json`.
2. Hace el barrido de la matriz con los dos backends.
3. Corre los 70 casos de punta a punta (PEP, PIP, política y servicios) comparando OPA con Python en cada decisión.
4. Prueba los fallos que deben denegar, el perfil de emergencia y la alerta por Cd2.

## Bitácora

La bitácora es un servicio aparte (`bitacora_svc/`), con su propia base y su propia cuenta (`bit_rw`, solo SELECT e INSERT).

- La aplicación nunca habla con esa base: usa el cliente `autorizacion/cliente_bitacora.py` (`BITACORA_URL` y, en la nube, `BITACORA_AUDIENCE`).
- El contrato completo, el esquema del evento y la fórmula del hash están en `bitacora_svc/BITACORA.md`.
- El servicio **no debe exponerse públicamente**: en la nube es privado (Cloud Run con IAM) y en dev escucha solo en loopback.

### Contrato y fórmula

- **Esquema cerrado** de textos, con tope de 16 KiB:
  - obligatorios: `accion`, `origen` y `resultado`;
  - opcionales: usuario, rol, huella de sesión, operación, objeto, finca, período, decisión, regla, huellas y versión de política.
- **Campos del servicio:** el servicio calcula `seq`, `sello`, `clase`, el seudónimo del usuario, `hash_previo` y `hash`, y descarta esos campos si llegan del cliente.
- **Hash:** `hash_n = SHA-256(hash_{n-1} en hex ASCII || JSON canónico del evento n sin hash ni hash_previo)`.
  - JSON canónico: claves ordenadas, separadores `(",", ":")`, `ensure_ascii=False` y UTF-8.
  - `hash_0` son 64 ceros.
- **Puntos de control:** `(seq, hash, fecha)` firmados con Ed25519 (`BITACORA_SIGNING_KEY`, distinta de `CERT_SIGNING_KEY`), en un almacén WORM: `puntos/{seq}.json`, local o en un bucket con retención bloqueada.
- **Seudónimo:** HMAC-SHA256(`BITACORA_SALT`, identificador), truncado a 32 hex. La sal es solo del servicio.

### Los datos no se pueden borrar

- Las tablas son de solo anexar: los disparadores rechazan UPDATE, DELETE y TRUNCATE para cualquier rol, incluido el propietario.
- **No escriba eventos de prueba en el esquema `bitacora`.** Las pruebas crean un esquema temporal por corrida y lo destruyen al final.
- La retención (10 años para certificación y administración, 24 meses para consulta y acceso) es política documentada, sin purga automática.

### Cuenta propietaria del esquema (solo dev)

El esquema lo aplica `bit_migrador`, propietario de esos objetos en la base de bitácora. Lo crea el dueño del proyecto con SQL, no desde el panel de Neon, para que no sea miembro de `neon_superuser`. La contraseña se define aparte y nunca se escribe en el repositorio:

```sql
CREATE ROLE bit_migrador LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
GRANT CONNECT, CREATE ON DATABASE neondb TO bit_migrador;
GRANT USAGE, CREATE ON SCHEMA public TO bit_migrador;
```

- Su cadena va en el secreto `DEV_DATABASE_URL_BITACORA_MIGRADOR`, que es **solo de desarrollo**.
- `entorno_dev.ps1 -Pruebas` la carga en `DATABASE_URL_BITACORA_MIGRADOR`, sin mostrarla.
- La cuenta de servicio de Cloud Run **no debe tener acceso** a ese secreto.
- Solo se usa para aplicar el esquema y para crear y destruir los esquemas temporales de las pruebas; nunca contra el negocio ni contra producción.

Aplicar el esquema en dev (si ya existe, no hace nada):

```powershell
. .\scripts\entorno_dev.ps1 -Pruebas
python scripts/aplicar_esquema_bitacora.py
```

### Servicio local

El servicio lee sus llaves del entorno. Para probarlo a mano, genere llaves efímeras en la sesión, sin mostrarlas ni guardarlas:

```powershell
. .\scripts\entorno_dev.ps1 -Pruebas
$generador = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$sal = New-Object byte[] 32; $generador.GetBytes($sal); $env:BITACORA_SALT = [Convert]::ToBase64String($sal)
$semilla = New-Object byte[] 32; $generador.GetBytes($semilla); $env:BITACORA_SIGNING_KEY = [Convert]::ToBase64String($semilla)
$env:BITACORA_DATABASE_URL = $env:DATABASE_URL_BITACORA
$env:BITACORA_WORM = 'local'; $env:BITACORA_WORM_DESTINO = Join-Path $env:TEMP 'bitacora_worm'
python -m bitacora_svc --puerto 8090
```

Con esas llaves efímeras los puntos solo se pueden verificar mientras dure la sesión. La llave y la sal reales se crean y se rotan fuera de Claude Code, solo por el dueño del proyecto.

### Verificador del auditor

```powershell
python scripts\verify_bitacora.py --eventos bitacora.jsonl --puntos carpeta_puntos --huella <SHA-256 de la clave pública> --cada 25
```

| Código | Significado |
| --- | --- |
| `0` | íntegra |
| `1` | cadena rota o con huecos |
| `2` | firma o clave no confiable |
| `3` | un punto no coincide (cadena reescrita) |
| `4` | formato inválido |
| `5` | faltan puntos (advertencia) |

`python manage.py verificar_bitacora` verifica desde el servicio. Si falla, alerta a R7 con prioridad alta. `python manage.py registrar_version_politica` registra la versión de la política cuando cambia.

### Eventos y fail-closed

- **PEP:**
  - registra el intento antes de ejecutar y, si no se registra, deniega;
  - registra el resultado después;
  - registra toda denegación con su regla;
  - registra las lecturas de R7 (Cd17) y, si no se registran, deniega.
- **Autenticación:** se registra con mejor esfuerzo. Si la bitácora no responde, el inicio de sesión sigue y queda un registro local del fallo, sin datos sensibles.
- **Proyección de R7 (`bitacora_r7`):** R7 consulta solo la clase certificación y la administración de cuentas, roles, ventanas, emergencia y alertas (O6 y O8). No ve accesos ni lecturas. El auditor ve todo dentro de su ventana.

### Pruebas

```powershell
. .\scripts\entorno_dev.ps1 -Pruebas
python manage.py test bitacora_svc
python scripts/probar_bitacora.py
```

`probar_bitacora.py` arranca el servicio en loopback, con llaves efímeras y un almacén WORM temporal. Crea y destruye dos esquemas temporales de bitácora y deja los conteos del negocio iguales.

### Despliegue

Ver `deploy/bitacora/Dockerfile`: imagen `python:3.15-slim`, usuario 10001, puerto 8080, gunicorn. Requiere:

- una cuenta de servicio propia;
- los secretos `DATABASE_URL_BITACORA`, `BITACORA_SALT` y `BITACORA_SIGNING_KEY`, con acceso solo para esa cuenta;
- un bucket con retención bloqueada (`BITACORA_WORM=gcs`);
- `roles/run.invoker` solo para la cuenta de la aplicación.

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
