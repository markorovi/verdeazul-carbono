# Contrato del PDP

Lo cumplen por igual la política Rego (`policy/autorizacion.rego`, en OPA) y el motor de referencia en Python (`autorizacion/motor.py`). Ambos leen la misma matriz (`autorizacion/matriz.json`) y las mismas constantes (`autorizacion/politica.json`).

OPA recibe la entrada en `POST /v1/data/verdeazul/autorizacion/decision`, con el cuerpo `{"input": ...}`.

## Entrada

Solo lleva identificadores seudónimos y banderas: ningún dato personal y ningún secreto.

```json
{
  "sujeto": {
    "id": "16 hex: seudónimo SHA-256 del UUID",
    "roles": ["R1"],
    "emergencia": null
  },
  "operacion": "O1.L",
  "hechos": {
    "asignacion_vigente": true,
    "propietario": true,
    "ventana_vigente": true,
    "segundo_factor": true,
    "proyeccion_disponible": true,
    "bitacora_disponible": true,
    "estado_visible_r2": true,
    "misma_region": true,
    "h2": {"disponible": true, "ajena": true, "wc": 5, "wl": 5, "laboral": true}
  },
  "parametros": {
    "h2_wc_laboral_blando": 10, "h2_wc_laboral_duro": 25,
    "h2_wc_fuera_blando": 3, "h2_wc_fuera_duro": 8,
    "h2_wl_blando": 40, "h2_wl_duro": 100
  }
}
```

- `sujeto.emergencia`: `null`, o `{"rol_suplido": "R1"}` (o `"R2"`) cuando la sesión usa un acceso de emergencia ya consumido.
- `hechos`: el PIP solo envía los que necesitan los permisos candidatos del sujeto. Un hecho ausente cuenta como falso.
- `h2`:
  - `wc` y `wl` son las parcelas ajenas distintas consultadas en la ventana corta y en la larga, sumando la actual si es ajena.
  - `laboral` indica si es lunes a viernes, de 6:00 a 18:00, hora de Costa Rica.
  - `disponible: false` significa que no se pudieron calcular los contadores (Cd9 degradado).
- `parametros`: umbrales de H2 leídos de PoliticaParametro. Si falta alguno, la política deniega por Cd9.

## Hechos y condiciones de política

| Condición | Hecho |
| --- | --- |
| Cd1 | `asignacion_vigente` |
| Cd2 | `propietario` |
| Cd3 | `ventana_vigente` |
| Cd4 | `segundo_factor` |
| Cd9 | `h2`, junto con `parametros` |
| Cd16 | `proyeccion_disponible` |
| Cd17 | `bitacora_disponible` |
| Cd21 | `estado_visible_r2` |
| Cd22 | `misma_region` |

## Salida

```json
{
  "permitir": true,
  "razon": null,
  "restricciones": ["2fa_reciente", "aviso_r7"],
  "condiciones_servicio": ["Cd5"],
  "proyeccion": "dueno",
  "registrar_lectura": false
}
```

- `razon`: en una denegación, la condición que falló o `"defecto"`; en una concesión, `null`.
- `restricciones`: lista ordenada con valores de `2fa_reciente`, `aviso_r7` y `cerrar_sesion`.
  - `2fa_reciente`: acciones críticas con Cd4 y Cd9 en umbral blando.
  - `aviso_r7`: Cd9 en umbral blando.
  - `cerrar_sesion`: solo acompaña la denegación por Cd9 en umbral duro.
- `condiciones_servicio`: las condiciones de servicio que exige el permiso concedido. El PEP comprueba que el servicio invocado declare aplicarlas.
- `proyeccion`: `tecnico`, `auditor` o `dueno` cuando el permiso incluye Cd16; si no, `null`.
- `registrar_lectura`: `true` cuando el permiso incluye Cd17.

## Composición

Se aplican en este orden; gana la primera que corresponda:

1. Operación desconocida o denegada a todos: `defecto`.
2. Perfil de emergencia fuera de su alcance: `Cd24`. Solo se permiten operaciones L de O1 a O5 con el rol suplido R1 o R2.
3. Ningún rol del sujeto tiene la operación: `defecto`.
4. Deny-overrides:
   - Cd9 en umbral duro, con `cerrar_sesion`.
   - Cd17 sin bitácora.
   - Exportación (O3.Ex) con H2 no disponible, como Cd9.
5. Se concede con el primer rol, en orden R1 a R7, cuyas condiciones de política se cumplen todas.
6. Si ninguno cumple, se deniega con la primera condición fallida del primer rol candidato.

Cualquier respuesta que no cumpla exactamente este contrato se trata como falla del PDP y deniega.
