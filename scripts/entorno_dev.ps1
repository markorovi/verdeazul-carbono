<#
.SYNOPSIS
    Carga en la sesion actual las variables de entorno para trabajar contra las ramas dev de Neon.

.DESCRIPTION
    Se usa con punto para que las variables queden en la sesion:
        . .\scripts\entorno_dev.ps1            # DATABASE_URL = app_rw
        . .\scripts\entorno_dev.ps1 -Migrador  # DATABASE_URL = migrador (para migraciones)
        . .\scripts\entorno_dev.ps1 -Pruebas   # ademas DATABASE_URL_APP y DATABASE_URL_MIGRADOR

    Lee las cadenas de Secret Manager (proyecto verdeazul-p2), la clave CLAVE_TOTP y la clave de
    firma CERT_SIGNING_KEY sin mostrarlas y sin escribirlas en disco. Si algo falla, no modifica
    ninguna variable.
    Este archivo es ASCII a proposito: PowerShell 5.1 lee los .ps1 sin BOM como ANSI.
#>
param(
    [switch]$Migrador,
    [switch]$Pruebas
)

& {
    $proyecto = 'verdeazul-p2'
    $secretoApp = 'DEV_DATABASE_URL_APP'
    $secretoMigrador = 'DEV_DATABASE_URL_MIGRADOR'
    $secretoBitacora = 'DEV_DATABASE_URL_BITACORA'
    $secretoClaveTotp = 'DEV_CLAVE_TOTP'
    $secretoFirma = 'DEV_CERT_SIGNING_KEY'
    $patronUrl = '[A-Za-z][A-Za-z0-9+.\-]*://\S+'

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

    function Write-ErrorSinCambios {
        param([string]$Mensaje)
        Write-Host "ERROR: $Mensaje" -ForegroundColor Red
        Write-Host 'Revise "gcloud auth login" y sus permisos. No se modifico ninguna variable de entorno.'
    }

    $gcloud = Find-Gcloud
    if (-not $gcloud) {
        Write-Host 'ERROR: no se encontro gcloud. Instale Google Cloud SDK o agreguelo al PATH.' -ForegroundColor Red
        Write-Host 'No se modifico ninguna variable de entorno.'
        return
    }

    $secretoPrincipal = if ($Migrador) { $secretoMigrador } else { $secretoApp }
    $rol = if ($Migrador) { 'migrador' } else { 'app_rw' }

    $necesarios = @($secretoPrincipal, $secretoBitacora, $secretoClaveTotp, $secretoFirma)
    if ($Pruebas) { $necesarios += @($secretoApp, $secretoMigrador) }

    # Se leen todos antes de definir nada: si uno falla, la sesion queda como estaba.
    $valores = @{}
    foreach ($nombre in ($necesarios | Select-Object -Unique)) {
        $resultado = Read-Secreto -Gcloud $gcloud -Nombre $nombre
        if (-not $resultado.Ok) {
            Write-ErrorSinCambios "no se pudo leer $nombre ($($resultado.Error))"
            return
        }
        $valores[$nombre] = $resultado.Valor
    }

    $env:ENTORNO = 'local'
    $env:SECRET_KEY = 'clave-local-de-desarrollo'
    $env:DATABASE_URL = $valores[$secretoPrincipal]
    $env:DATABASE_URL_BITACORA = $valores[$secretoBitacora]
    $env:CLAVE_TOTP = $valores[$secretoClaveTotp]
    $env:CERT_SIGNING_KEY = $valores[$secretoFirma]
    if ($Pruebas) {
        $env:DATABASE_URL_APP = $valores[$secretoApp]
        $env:DATABASE_URL_MIGRADOR = $valores[$secretoMigrador]
    }

    Write-Host "Entorno dev cargado: DATABASE_URL = $rol; valores no mostrados"
    if ($Pruebas) {
        Write-Host 'Pruebas: DATABASE_URL_APP y DATABASE_URL_MIGRADOR definidas; valores no mostrados'
    }
}
