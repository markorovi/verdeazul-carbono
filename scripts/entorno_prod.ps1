<#
.SYNOPSIS
    Carga en la sesion actual el entorno de PRODUCCION para el corte. Solo lo usa el dueno del
    proyecto; nunca se ejecuta desde Claude Code.

.DESCRIPTION
    Se usa con punto, con exactamente uno de los dos modos:
        . .\scripts\entorno_prod.ps1 -Migrador   # DATABASE_URL = migrador (migraciones)
        . .\scripts\entorno_prod.ps1 -App        # DATABASE_URL = app_rw, y CLAVE_TOTP

    Exige escribir PRODUCCION. Lee los secretos de produccion de Secret Manager (proyecto
    verdeazul-p2) sin mostrarlos y sin escribirlos en disco; si falta alguno no define nada.
    SECRET_KEY es aleatoria (no es la de produccion) y ENTORNO se elimina para que rija la
    configuracion estricta. Salir-Produccion borra lo cargado y restaura el prompt.
    Este archivo es ASCII a proposito: PowerShell 5.1 lee los .ps1 sin BOM como ANSI.
#>
param(
    [switch]$Migrador,
    [switch]$App
)

& {
    $proyecto = 'verdeazul-p2'
    $patronUrl = '[A-Za-z][A-Za-z0-9+.\-]*://\S+'
    $variablesCargadas = @('DATABASE_URL', 'SECRET_KEY', 'CLAVE_TOTP', 'VERDEAZUL_PROD')
    # Variables de dev que no deben convivir con una sesion de produccion.
    $variablesDev = @('DATABASE_URL_APP', 'DATABASE_URL_MIGRADOR', 'DATABASE_URL_BITACORA', 'CLAVE_TOTP')

    function Find-Gcloud {
        foreach ($nombre in @('gcloud', 'gcloud.cmd')) {
            $comando = Get-Command $nombre -CommandType Application -ErrorAction SilentlyContinue |
                Select-Object -First 1
            if ($comando) { return $comando.Source }
        }
        if ($env:LOCALAPPDATA) {
            $ruta = Join-Path $env:LOCALAPPDATA 'Google\Cloud SDK\google-cloud-sdk\bin\gcloud.cmd'
            if (Test-Path -LiteralPath $ruta) { return $ruta }
        }
        return $null
    }

    function Read-Secreto {
        param([string]$Gcloud, [string]$Nombre)
        $ErrorActionPreference = 'Continue'
        $salida = & $Gcloud secrets versions access latest "--secret=$Nombre" "--project=$proyecto" 2>&1
        $codigo = $LASTEXITCODE
        $errores = @($salida | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] } |
            ForEach-Object { $_.ToString() })
        $lineas = @($salida | Where-Object { $_ -isnot [System.Management.Automation.ErrorRecord] } |
            ForEach-Object { [string]$_ })
        if ($codigo -ne 0) {
            $detalle = @($errores | Where-Object { $_ -match '^ERROR' } | Select-Object -Last 1)
            if (-not $detalle) { $detalle = @($errores | Select-Object -Last 1) }
            $texto = ($detalle -join ' ') -replace $patronUrl, '[REDACTADO]'
            return @{ Ok = $false; Error = "gcloud termino con codigo $codigo. $texto" }
        }
        $valor = ($lineas -join '').Trim()
        if (-not $valor) { return @{ Ok = $false; Error = 'el secreto esta vacio.' } }
        return @{ Ok = $true; Valor = $valor }
    }

    function New-ClaveAleatoria {
        param([int]$Largo)
        # 64 simbolos: el modulo sobre un byte no introduce sesgo.
        $alfabeto = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_'
        $bytes = New-Object byte[] $Largo
        $generador = [System.Security.Cryptography.RandomNumberGenerator]::Create()
        try { $generador.GetBytes($bytes) } finally { $generador.Dispose() }
        return -join ($bytes | ForEach-Object { $alfabeto[$_ % 64] })
    }

    if ($Migrador -eq $App) {
        Write-Host 'ERROR: indique exactamente uno de -Migrador o -App. No se cargo nada.' -ForegroundColor Red
        return
    }
    if ($env:VERDEAZUL_PROD) {
        Write-Host 'ERROR: ya hay un entorno de produccion cargado. Ejecute Salir-Produccion primero.' -ForegroundColor Red
        return
    }
    $modo = if ($Migrador) { 'migrador' } else { 'app' }

    Write-Host "Va a cargar el entorno de PRODUCCION en modo $modo." -ForegroundColor Yellow
    $confirmacion = Read-Host 'Escriba PRODUCCION para continuar'
    if ($confirmacion -cne 'PRODUCCION') {
        Write-Host 'Abortado: no se escribio PRODUCCION. No se cargo nada.' -ForegroundColor Red
        return
    }

    $gcloud = Find-Gcloud
    if (-not $gcloud) {
        Write-Host 'ERROR: no se encontro gcloud. Instale Google Cloud SDK o agreguelo al PATH. No se cargo nada.' -ForegroundColor Red
        return
    }

    $necesarios = if ($Migrador) { @('DATABASE_URL_MIGRADOR') } else { @('DATABASE_URL_APP', 'CLAVE_TOTP') }

    # Se leen todos antes de definir nada: si uno falla, la sesion queda como estaba.
    $valores = @{}
    foreach ($nombre in $necesarios) {
        $resultado = Read-Secreto -Gcloud $gcloud -Nombre $nombre
        if (-not $resultado.Ok) {
            Write-Host "ERROR: no se pudo leer el secreto $nombre ($($resultado.Error))" -ForegroundColor Red
            Write-Host 'Revise "gcloud auth login" y sus permisos. No se cargo nada.'
            return
        }
        $valores[$nombre] = $resultado.Valor
    }

    foreach ($nombre in $variablesDev) {
        Remove-Item -Path "Env:$nombre" -ErrorAction SilentlyContinue
    }
    Remove-Item -Path 'Env:ENTORNO' -ErrorAction SilentlyContinue

    if ($Migrador) {
        $env:DATABASE_URL = $valores['DATABASE_URL_MIGRADOR']
    } else {
        $env:DATABASE_URL = $valores['DATABASE_URL_APP']
        $env:CLAVE_TOTP = $valores['CLAVE_TOTP']
    }
    $env:SECRET_KEY = New-ClaveAleatoria -Largo 50
    $env:VERDEAZUL_PROD = $modo

    $promptOriginal = (Get-Item -Path 'function:prompt').ScriptBlock
    $etiqueta = "[PRODUCCION-$modo] "
    Set-Item -Path 'function:global:prompt' -Value ({ $etiqueta + (& $promptOriginal) }.GetNewClosure())

    $salir = {
        foreach ($nombre in $variablesCargadas) {
            Remove-Item -Path "Env:$nombre" -ErrorAction SilentlyContinue
        }
        Set-Item -Path 'function:global:prompt' -Value $promptOriginal
        Remove-Item -Path 'function:global:Salir-Produccion' -ErrorAction SilentlyContinue
        Write-Host 'Entorno de produccion descargado; prompt restaurado.'
    }.GetNewClosure()
    Set-Item -Path 'function:global:Salir-Produccion' -Value $salir

    Write-Host ''
    Write-Host "ENTORNO DE PRODUCCION CARGADO (modo $modo); valores no mostrados." -ForegroundColor Red
    Write-Host 'Todo comando de esta sesion actua sobre la base de produccion.' -ForegroundColor Red
    Write-Host 'SECRET_KEY es aleatoria (no es la de produccion). Para salir: Salir-Produccion' -ForegroundColor Yellow
}
