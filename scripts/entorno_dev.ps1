<#
.SYNOPSIS
    Carga en la sesion actual las variables de entorno para trabajar contra las ramas dev de Neon.

.DESCRIPTION
    Se usa con punto para que las variables queden en la sesion:
        . .\scripts\entorno_dev.ps1            # DATABASE_URL = app_rw
        . .\scripts\entorno_dev.ps1 -Migrador  # DATABASE_URL = migrador (para migraciones)

    Lee las cadenas de Secret Manager (proyecto verdeazul-p2) sin mostrarlas y sin escribirlas
    en disco. Si algo falla, no modifica ninguna variable.
    Este archivo es ASCII a proposito: PowerShell 5.1 lee los .ps1 sin BOM como ANSI.
#>
param(
    [switch]$Migrador
)

& {
    $proyecto = 'verdeazul-p2'

    # Localizar gcloud: PATH, luego la instalacion por usuario.
    $gcloud = $null
    foreach ($nombre in @('gcloud', 'gcloud.cmd')) {
        $comando = Get-Command $nombre -CommandType Application -ErrorAction SilentlyContinue |
            Select-Object -First 1
        if ($comando) { $gcloud = $comando.Source; break }
    }
    if (-not $gcloud -and $env:LOCALAPPDATA) {
        $ruta = Join-Path $env:LOCALAPPDATA 'Google\Cloud SDK\google-cloud-sdk\bin\gcloud.cmd'
        if (Test-Path -LiteralPath $ruta) { $gcloud = $ruta }
    }
    if (-not $gcloud) {
        Write-Host 'ERROR: no se encontro gcloud. Instale Google Cloud SDK o agreguelo al PATH.' -ForegroundColor Red
        Write-Host 'No se modifico ninguna variable de entorno.'
        return
    }

    function Read-Secreto {
        param([string]$Nombre)
        $ErrorActionPreference = 'Continue'
        $salida = & $gcloud secrets versions access latest "--secret=$Nombre" "--project=$proyecto" 2>&1
        $codigo = $LASTEXITCODE
        $errores = @($salida | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] } |
            ForEach-Object { $_.ToString() })
        $lineas = @($salida | Where-Object { $_ -isnot [System.Management.Automation.ErrorRecord] } |
            ForEach-Object { [string]$_ })
        if ($codigo -ne 0) {
            $detalle = @($errores | Where-Object { $_ -match '^ERROR' } | Select-Object -Last 1)
            if (-not $detalle) { $detalle = @($errores | Select-Object -Last 1) }
            $texto = ($detalle -join ' ') -replace '[A-Za-z][A-Za-z0-9+.\-]*://\S+', '[REDACTADO]'
            return @{ Ok = $false; Error = "gcloud termino con codigo $codigo. $texto" }
        }
        $valor = ($lineas -join '').Trim()
        if (-not $valor) { return @{ Ok = $false; Error = 'el secreto esta vacio.' } }
        return @{ Ok = $true; Valor = $valor }
    }

    $nombrePrincipal = if ($Migrador) { 'DEV_DATABASE_URL_MIGRADOR' } else { 'DEV_DATABASE_URL_APP' }
    $rol = if ($Migrador) { 'migrador' } else { 'app_rw' }

    $principal = Read-Secreto $nombrePrincipal
    if (-not $principal.Ok) {
        Write-Host "ERROR: no se pudo leer $nombrePrincipal ($($principal.Error))" -ForegroundColor Red
        Write-Host 'Revise "gcloud auth login" y sus permisos. No se modifico ninguna variable de entorno.'
        return
    }
    $bitacora = Read-Secreto 'DEV_DATABASE_URL_BITACORA'
    if (-not $bitacora.Ok) {
        Write-Host "ERROR: no se pudo leer DEV_DATABASE_URL_BITACORA ($($bitacora.Error))" -ForegroundColor Red
        Write-Host 'Revise "gcloud auth login" y sus permisos. No se modifico ninguna variable de entorno.'
        return
    }

    $env:ENTORNO = 'local'
    $env:SECRET_KEY = 'clave-local-de-desarrollo'
    $env:DATABASE_URL = $principal.Valor
    $env:DATABASE_URL_BITACORA = $bitacora.Valor

    Write-Host "Entorno dev cargado: DATABASE_URL = $rol; valores no mostrados"
}
