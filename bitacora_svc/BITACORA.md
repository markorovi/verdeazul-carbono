# Bitácora de Verdeazul Carbono

La bitácora es un servicio aparte (`bitacora_svc`), con su propia base y su propia cuenta de base (`bit_rw`, solo SELECT e INSERT). La aplicación nunca habla con esa base: habla con el servicio, que solo ofrece anexar y consultar.

## Exposición del servicio

El servicio **no debe exponerse públicamente**.

- En la nube es privado: Cloud Run con IAM. Solo la cuenta de servicio de la aplicación tiene `roles/run.invoker`, y Cloud Run valida el token de identidad antes de cada petición.
- En dev escucha solo en `127.0.0.1`.

## API

| Ruta | Uso |
| --- | --- |
| `POST /eventos` | Anexa un evento. Devuelve `{"seq", "hash"}` (201). |
| `GET /eventos` | Consulta por `usuario_id`, `objeto_tipo`, `objeto_id`, `clase` (repetible), `desde`, `hasta`, `limite` (máximo 500) y `orden` (`desc`). |
| `GET /exportar?desde=&hasta=` | La cadena en JSON lines, para el auditor. |
| `GET /puntos` | Puntos de control registrados. |
| `POST /puntos` | Crea un punto bajo demanda en el último seq. 201 si es nuevo; 200 si ya existía, sin sobrescribirlo. |
| `POST /verificar` | Verifica la cadena y los puntos; devuelve `{"integra", "codigo", "eventos", "puntos", "detalle"}`. |
| `GET /salud` | `{"estado": "ok" o "degradado", "ultimo_seq", "puntos_pendientes"}`; 503 si la base no responde. |

- Cualquier otra ruta responde 404, y otro método en una ruta conocida, 405.
- Un cuerpo de más de 16 KiB se rechaza con 413.
- Los errores no traen detalles internos.

## Esquema del evento

El esquema es cerrado: se rechaza todo campo desconocido, de tipo incorrecto o que exceda su largo (400). Todos los valores son textos y cualquiera puede omitirse, salvo los obligatorios: `accion`, `origen` y `resultado`.

| Campo | Contenido |
| --- | --- |
| `accion` | `intento`, `resultado`, `denegacion`, `lectura`, `exportacion`, `inicio_sesion`, `segundo_factor`, `bloqueo` o `version_politica` |
| `usuario_id` | Identificador de la persona. **No se guarda**: el servicio guarda su seudónimo en `usuario`. |
| `rol_activo` | `R1` a `R7`, separados por comas |
| `sesion` | SHA-256 (64 hex) de la clave de sesión. La calcula la aplicación; el servicio nunca recibe la clave. |
| `operacion` | Operación de la matriz, por ejemplo `O1.Ap` |
| `servicio` | Servicio de negocio invocado |
| `objeto_tipo` | `parcela`, `medicion`, `certificado`, `enmienda`, `periodo`, `finca`, `cuenta`, `alerta`, `ventana`, `acceso`, `politica` o `ninguno` |
| `objeto_id` | Identificador del objeto. Si el tipo es `cuenta`, el servicio lo seudonimiza. |
| `finca_id`, `periodo_id` | UUID, cuando el objeto los tiene |
| `decision`, `regla` | `concedido` o `denegado`; la condición (`Cd8`, `defecto`, ...) |
| `motivo` | Motivo de un evento de autenticación (`contrasena_invalida`, ...) |
| `version_politica` | SHA-256 de la matriz, las constantes y la política Rego |
| `huella_anterior`, `huella_posterior` | SHA-256 del valor anterior y del posterior en escrituras |
| `huella_exportacion` | SHA-256 de los bytes exportados |
| `origen` | `pep`, `autenticacion` o `sistema` |
| `resultado` | `exito`, `fallo`, `concedido`, `denegado`, `rechazado` o `error` |
| `error_clase` | Clase de la excepción de una falla del servicio (nunca su mensaje) |

- **Calculados por el servicio:** `seq`, `sello` (ISO 8601 UTC con microsegundos y `Z`), `clase` (de la acción y del objeto de la operación), `usuario` (seudónimo), `hash_previo` y `hash`.
- **Campos que se ignoran si llegan del cliente:** `seq`, `sello`, `fecha`, `hash`, `hash_previo`, `clase` y `usuario`. El servicio no confía en ellos.
- **Datos personales:** nunca viajan contraseñas, tokens ni más datos personales que los necesarios (Ley 8968).

## Fórmula del hash

```
canonico(x) = UTF-8 de json.dumps(x, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
cuerpo_n    = el evento n exportado, SIN las claves "hash" ni "hash_previo"
              (incluye seq, sello, clase y usuario)
hash_0      = "0" * 64
hash_n      = hex( SHA-256( ASCII(hash_{n-1}) || canonico(cuerpo_n) ) )
```

- El JSON solo contiene textos, enteros y nulos, nunca números con decimales, así que releerlo y canonizarlo de nuevo reproduce los mismos bytes.
- La base repite la comprobación en un disparador: `encode(sha256(convert_to(hash_previo || cuerpo, 'UTF8')), 'hex')`. También exige seq contiguo, `hash_previo` igual al último hash y un sello que no retroceda.

Ejemplo, el primer evento:

```
hash_1 = SHA-256( "000...000" (64 ceros) || {"accion":"intento","clase":"certificacion",...,"seq":1,"sello":"..."} )
```

## Puntos de control

- **Frecuencia:** uno cada `BITACORA_PUNTO_CADA` eventos (25 por defecto) y otro bajo demanda. Hay un punto por seq y nunca se sobrescribe.
- **Firma:** la carga útil canónica se firma con Ed25519, con la llave de la bitácora (`BITACORA_SIGNING_KEY`), distinta de la de certificados.

```json
{"payload": {"version": 1, "seq": 25, "hash": "<hash del evento 25>", "fecha": "...Z", "alg": "Ed25519", "key_id": "<16 hex>"},
 "firma": "<base64 de Ed25519(canonico(payload))>",
 "clave_publica": "<base64 de los 32 bytes de la clave pública>"}
```

- **`key_id`:** los primeros 16 hex del SHA-256 de la clave pública cruda.
- **Almacén WORM:**
  - un objeto por punto: `puntos/{seq con 12 dígitos}.json`;
  - backend local: directorio con creación exclusiva;
  - backend GCS: bucket con precondición de no existencia y retención bloqueada, que se configura en el bucket.
- **Si el almacén falla:** el evento ya anexado se conserva, `/salud` informa `degradado` y el siguiente anexo reintenta.

## Verificación (auditor)

```
python scripts/verify_bitacora.py --eventos bitacora.jsonl --puntos carpeta_puntos --huella <SHA-256 de la clave pública> [--cada 25]
```

El verificador solo usa la biblioteca estándar y `cryptography`. Comprueba:

- la secuencia contigua desde 1;
- el encadenamiento;
- la firma de cada punto, con la clave confiable;
- que cada punto coincida con el hash de su seq;
- que existan los puntos esperados.

| Código | Significado |
| --- | --- |
| 0 | íntegra |
| 1 | cadena rota o secuencia con huecos |
| 2 | firma de un punto inválida o clave no confiable |
| 3 | un punto no coincide con la cadena (reescritura completa) |
| 4 | formato inválido |
| 5 | faltan puntos esperados (advertencia) |

`manage.py verificar_bitacora` llama a `POST /verificar`. Si falla o el servicio no responde, registra una alerta prioritaria para R7 (tipo `bitacora_integridad`).

## Seudonimización

- **Cálculo:** `usuario` = HMAC-SHA256(`BITACORA_SALT`, identificador), truncado a 32 hex. Lo mismo para `objeto_id` cuando el objeto es una cuenta.
- **La sal:** es una llave secreta solo del servicio. En la nube va en Secret Manager, con acceso únicamente de su cuenta de servicio.
- **Consultas por usuario:** reciben el identificador y el servicio calcula el seudónimo.
- **Destruir la sal** desasocia a las personas sin romper la cadena, porque el hash cubre el seudónimo, no el identificador.
- **Desviación de la Parte 1:** el mecanismo por persona se reduce a una llave global, por la escala del proyecto.

## Retención

La retención se modela con la columna `clase`. **No hay purga automática.**

| Clase | Retención |
| --- | --- |
| `certificacion` (mediciones, presentación, aprobación, devolución, emisión, anulación, enmienda, períodos) | 10 años desde la emisión |
| `consulta` (lecturas y exportaciones) | 24 meses |
| `acceso` (autenticación y denegaciones) | 24 meses |
| `administracion` (catálogo, cuentas, roles, ventanas, emergencia, alertas y versión de política) | 10 años |

Como la tabla es de solo anexar, la depuración, cuando corresponda, necesita un procedimiento explícito del dueño fuera del servicio.

## Configuración del servicio

| Variable | Contenido |
| --- | --- |
| `BITACORA_DATABASE_URL` | Cadena de `bit_rw` |
| `BITACORA_ESQUEMA` | Esquema; por defecto `bitacora` |
| `BITACORA_SALT` | 32 bytes o más, en base64 |
| `BITACORA_SIGNING_KEY` | Semilla Ed25519 de 32 bytes, en base64 |
| `BITACORA_WORM` | `local` o `gcs` |
| `BITACORA_WORM_DESTINO` | Directorio o bucket |
| `BITACORA_PUNTO_CADA` | Eventos entre puntos de control |

Sin `BITACORA_WORM` y su destino, el servicio no arranca. Las llaves nunca se imprimen.
