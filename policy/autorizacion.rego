# Política de autorización de Verdeazul Carbono (PDP).
#
# La matriz (data.verdeazul.matriz) y las constantes (data.verdeazul.politica) se cargan como datos
# desde autorizacion/matriz.json y autorizacion/politica.json, los mismos archivos que usa el motor
# de referencia en Python (autorizacion/motor.py). La entrada solo trae identificadores seudónimos y
# banderas calculadas por el PIP; nunca datos personales.
#
# Composición: denegación por defecto; deny-overrides (Cd9 duro, Cd17 sin bitácora y exportación con
# H2 degradado anulan cualquier permiso); se concede si algún rol del sujeto tiene la operación con
# todas sus condiciones de política verdaderas. Las condiciones de servicio no se evalúan aquí.
package verdeazul.autorizacion

matriz := data.verdeazul.matriz

politica := data.verdeazul.politica

operacion := input.operacion

hechos := object.get(input, "hechos", {})

parametros := object.get(input, "parametros", {})

h2 := object.get(hechos, "h2", {})

objeto := split(operacion, ".")[0]

tipo := split(operacion, ".")[1]

permisos := matriz.operaciones[operacion]

condiciones_politica := {c | some c in matriz.condiciones_politica}

condiciones_servicio := {c | some c in matriz.condiciones_servicio}

parametros_h2 := [
	"h2_wc_laboral_blando",
	"h2_wc_laboral_duro",
	"h2_wc_fuera_blando",
	"h2_wc_fuera_duro",
	"h2_wl_blando",
	"h2_wl_duro",
]

# --------------------------------------------------------------------------- sujeto

en_emergencia if object.get(input.sujeto, "emergencia", null) != null

roles_efectivos := [input.sujeto.emergencia.rol_suplido] if {
	en_emergencia
} else := sort({r | some r in object.get(input.sujeto, "roles", [])})

# El perfil de emergencia solo lee (L) con el rol suplido, R1 o R2, sobre O1 a O5.
emergencia_prohibida if not input.sujeto.emergencia.rol_suplido in politica.roles_suplibles

emergencia_prohibida if tipo != "L"

emergencia_prohibida if not objeto in politica.objetos_emergencia

candidatos := [r | some r in roles_efectivos; r in object.keys(permisos)]

# --------------------------------------------------------------------------- H2 (Cd9)

h2_disponible if h2.disponible == true

parametros_h2_completos if {
	every p in parametros_h2 {
		is_number(parametros[p])
	}
	is_number(h2.wc)
	is_number(h2.wl)
}

franja := "laboral" if h2.laboral == true

else := "fuera"

h2_calculado := "duro" if {
	h2.wc >= parametros[sprintf("h2_wc_%s_duro", [franja])]
} else := "duro" if {
	h2.wl >= parametros.h2_wl_duro
} else := "blando" if {
	h2.wc >= parametros[sprintf("h2_wc_%s_blando", [franja])]
} else := "blando" if {
	h2.wl >= parametros.h2_wl_blando
} else := "ok"

default h2_estado := "denegado"

# Sin contadores disponibles falla degradado: solo concede lo que no es ajeno.
h2_estado := "ok" if {
	not h2_disponible
	h2.ajena == false
}

h2_estado := h2_calculado if {
	h2_disponible
	parametros_h2_completos
}

# --------------------------------------------------------------------------- condiciones de política

cumple("Cd1") if hechos.asignacion_vigente == true

cumple("Cd2") if hechos.propietario == true

cumple("Cd3") if hechos.ventana_vigente == true

cumple("Cd4") if hechos.segundo_factor == true

cumple("Cd9") if h2_estado in {"ok", "blando"}

cumple("Cd16") if hechos.proyeccion_disponible == true

cumple("Cd17") if hechos.bitacora_disponible == true

cumple("Cd21") if hechos.estado_visible_r2 == true

cumple("Cd22") if hechos.misma_region == true

fallidas(rol) := [c |
	some c in permisos[rol]
	c in condiciones_politica
	not cumple(c)
]

satisfechos := [r | some r in candidatos; count(fallidas(r)) == 0]

# --------------------------------------------------------------------------- deny-overrides

anula_cd9 if {
	h2_estado == "duro"
	some r in candidatos
	"Cd9" in permisos[r]
}

anula_cd17 if {
	not hechos.bitacora_disponible == true
	some r in candidatos
	"Cd17" in permisos[r]
}

anula_exportacion if {
	operacion == "O3.Ex"
	not h2_disponible
}

# --------------------------------------------------------------------------- salida

denegar(razon) := {
	"permitir": false,
	"razon": razon,
	"restricciones": [],
	"condiciones_servicio": [],
	"proyeccion": null,
	"registrar_lectura": false,
}

requiere("2fa_reciente", rol) if {
	"Cd4" in permisos[rol]
	operacion in politica.operaciones_criticas
}

requiere("2fa_reciente", rol) if {
	"Cd9" in permisos[rol]
	h2_estado == "blando"
}

requiere("aviso_r7", rol) if {
	"Cd9" in permisos[rol]
	h2_estado == "blando"
}

proyeccion(rol) := politica.proyecciones[rol] if "Cd16" in permisos[rol]

else := null

conceder(rol) := {
	"permitir": true,
	"razon": null,
	"restricciones": sort([r | some r in ["2fa_reciente", "aviso_r7"]; requiere(r, rol)]),
	"condiciones_servicio": [c | some c in permisos[rol]; c in condiciones_servicio],
	"proyeccion": proyeccion(rol),
	"registrar_lectura": "Cd17" in permisos[rol],
}

decision := denegar("defecto") if {
	not operacion in object.keys(matriz.operaciones)
} else := denegar("defecto") if {
	count(permisos) == 0
} else := denegar("Cd24") if {
	en_emergencia
	emergencia_prohibida
} else := denegar("defecto") if {
	count(candidatos) == 0
} else := object.union(denegar("Cd9"), {"restricciones": ["cerrar_sesion"]}) if {
	anula_cd9
} else := denegar("Cd17") if {
	anula_cd17
} else := denegar("Cd9") if {
	anula_exportacion
} else := conceder(satisfechos[0]) if {
	count(satisfechos) > 0
} else := denegar(fallidas(candidatos[0])[0])
