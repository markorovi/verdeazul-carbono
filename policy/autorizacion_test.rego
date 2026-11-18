# Pruebas de la política: una por condición de política, H2, deny-overrides y perfil de emergencia.
package verdeazul.autorizacion_test

import data.verdeazul.autorizacion

parametros := {
	"h2_wc_laboral_blando": 10,
	"h2_wc_laboral_duro": 25,
	"h2_wc_fuera_blando": 3,
	"h2_wc_fuera_duro": 8,
	"h2_wl_blando": 40,
	"h2_wl_duro": 100,
}

h2_ok := {"disponible": true, "ajena": false, "wc": 0, "wl": 0, "laboral": true}

todos := {
	"asignacion_vigente": true,
	"propietario": true,
	"ventana_vigente": true,
	"segundo_factor": true,
	"proyeccion_disponible": true,
	"bitacora_disponible": true,
	"estado_visible_r2": true,
	"misma_region": true,
	"h2": h2_ok,
}

entrada(op, roles, cambios) := {
	"operacion": op,
	"sujeto": {"id": "0123456789abcdef", "roles": roles, "emergencia": null},
	"hechos": object.union(todos, cambios),
	"parametros": parametros,
}

emergencia(op, rol, roles) := {
	"operacion": op,
	"sujeto": {"id": "0123456789abcdef", "roles": roles, "emergencia": {"rol_suplido": rol}},
	"hechos": todos,
	"parametros": parametros,
}

h2(wc, laboral) := {"disponible": true, "ajena": true, "wc": wc, "wl": wc, "laboral": laboral}

test_concede_con_todas_las_condiciones if {
	d := autorizacion.decision with input as entrada("O1.Rg", ["R1"], {})
	d.permitir
	d.condiciones_servicio == ["Cd5"]
	d.restricciones == []
}

test_cd1_sin_asignacion if {
	d := autorizacion.decision with input as entrada("O1.Rg", ["R1"], {"asignacion_vigente": false})
	not d.permitir
	d.razon == "Cd1"
}

test_cd2_otro_dueno if {
	d := autorizacion.decision with input as entrada("O3.L", ["R6"], {"propietario": false})
	d.razon == "Cd2"
}

test_cd3_fuera_de_ventana if {
	d := autorizacion.decision with input as entrada("O1.L", ["R5"], {"ventana_vigente": false})
	d.razon == "Cd3"
}

test_cd4_sin_segundo_factor if {
	d := autorizacion.decision with input as entrada("O1.Ap", ["R2"], {"segundo_factor": false})
	d.razon == "Cd4"
}

test_cd4_accion_critica_pide_segundo_factor_reciente if {
	d := autorizacion.decision with input as entrada("O1.Ap", ["R2"], {})
	d.permitir
	d.restricciones == ["2fa_reciente"]
	d.condiciones_servicio == ["Cd7", "Cd8", "Cd10"]
}

test_cd9_blando_concede_con_restricciones if {
	d := autorizacion.decision with input as entrada("O1.L", ["R1"], {"h2": h2(12, true)})
	d.permitir
	d.restricciones == ["2fa_reciente", "aviso_r7"]
}

test_cd9_duro_deniega_y_cierra_sesion if {
	d := autorizacion.decision with input as entrada("O1.L", ["R1"], {"h2": h2(25, true)})
	d.razon == "Cd9"
	d.restricciones == ["cerrar_sesion"]
}

test_cd9_umbral_fuera_de_horario if {
	blando := autorizacion.decision with input as entrada("O1.L", ["R1"], {"h2": h2(5, false)})
	blando.restricciones == ["2fa_reciente", "aviso_r7"]
	duro := autorizacion.decision with input as entrada("O1.L", ["R1"], {"h2": h2(8, false)})
	duro.razon == "Cd9"
}

test_cd9_ventana_larga if {
	d := autorizacion.decision with input as entrada("O1.L", ["R1"], {"h2": {"disponible": true, "ajena": true, "wc": 1, "wl": 100, "laboral": true}})
	d.razon == "Cd9"
}

test_cd9_degradado if {
	habitual := autorizacion.decision with input as entrada("O1.L", ["R1"], {"h2": {"disponible": false, "ajena": false}})
	habitual.permitir
	ajena := autorizacion.decision with input as entrada("O1.L", ["R1"], {"h2": {"disponible": false, "ajena": true}})
	ajena.razon == "Cd9"
	exportar := autorizacion.decision with input as entrada("O3.Ex", ["R6"], {"h2": {"disponible": false, "ajena": false}})
	exportar.razon == "Cd9"
}

test_cd9_sin_umbrales_deniega if {
	sin_umbrales := object.remove(entrada("O1.L", ["R1"], {}), ["parametros"])
	d := autorizacion.decision with input as sin_umbrales
	d.razon == "Cd9"
}

test_cd16_proyeccion if {
	d := autorizacion.decision with input as entrada("O3.L", ["R6"], {})
	d.proyeccion == "dueno"
	sin := autorizacion.decision with input as entrada("O3.L", ["R6"], {"proyeccion_disponible": false})
	sin.razon == "Cd16"
}

test_cd17_registra_lectura if {
	d := autorizacion.decision with input as entrada("O1.L", ["R7"], {})
	d.registrar_lectura
	sin := autorizacion.decision with input as entrada("O1.L", ["R7"], {"bitacora_disponible": false})
	sin.razon == "Cd17"
}

test_cd21_estado_para_r2 if {
	d := autorizacion.decision with input as entrada("O1.L", ["R2"], {"estado_visible_r2": false})
	d.razon == "Cd21"
}

test_cd22_region if {
	d := autorizacion.decision with input as entrada("O1.L", ["R1"], {"misma_region": false})
	d.razon == "Cd22"
}

test_defecto if {
	nadie := autorizacion.decision with input as entrada("O1.MdC", ["R7"], {})
	nadie.razon == "defecto"
	sin_rol := autorizacion.decision with input as entrada("O1.L", ["R3"], {})
	sin_rol.razon == "defecto"
	desconocida := autorizacion.decision with input as entrada("O9.L", ["R7"], {})
	desconocida.razon == "defecto"
}

test_cd9_duro_anula_otro_permiso if {
	d := autorizacion.decision with input as entrada("O5.L", ["R1", "R3"], {"h2": h2(30, true)})
	d.razon == "Cd9"
}

test_emergencia_lee_con_el_rol_suplido if {
	d := autorizacion.decision with input as emergencia("O1.L", "R2", [])
	d.permitir
	sin_estado := autorizacion.decision with input as object.union(emergencia("O1.L", "R2", []), {"hechos": object.union(todos, {"estado_visible_r2": false})})
	sin_estado.razon == "Cd21"
}

test_emergencia_no_escribe_ni_sale_de_o1_a_o5 if {
	aprobar := autorizacion.decision with input as emergencia("O1.Ap", "R2", ["R7"])
	aprobar.razon == "Cd24"
	cuentas := autorizacion.decision with input as emergencia("O6.L", "R2", [])
	cuentas.razon == "Cd24"
	bitacora := autorizacion.decision with input as emergencia("O7.L", "R1", [])
	bitacora.razon == "Cd24"
	exportar := autorizacion.decision with input as emergencia("O3.Ex", "R2", [])
	exportar.razon == "Cd24"
}

test_emergencia_rol_no_suplible if {
	d := autorizacion.decision with input as emergencia("O1.L", "R7", [])
	d.razon == "Cd24"
}
