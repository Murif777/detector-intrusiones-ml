<#
.SYNOPSIS
    Menú interactivo de la demo NIDS-ML. Solo requiere Docker instalado.

.DESCRIPTION
    Levanta victim, nids (con detector indefinido) y dashboard, y permite lanzar
    los ataques de a uno para ver las alertas aparecer en el panel web.

    El script se ubica solo en la carpeta del repositorio. No usa Python ni uv
    del host: todo corre dentro de los contenedores.

    Al entrar al menú abre el dashboard si no estaba corriendo y muestra el link
    http://localhost:8501. No abre el navegador automáticamente.

    Al terminar cada ataque detiene nids de forma limpia (SIGTERM) para que
    vuelque los flujos que siguen abiertos (por ejemplo, SYNs sin respuesta) y
    recién entonces cuenta las alertas nuevas. Después lo vuelve a levantar,
    siempre con NIDS_DURATION=0, para encadenar el ataque siguiente.

.PARAMETER Attack
    Corre un solo ataque sin mostrar el menú y termina. Valores: 1, 2, 3 o all.
    Es útil para automatizar y para probar el script. En este modo no pregunta
    nada y NO levanta el dashboard (solo victim y nids).

.EXAMPLE
    .\demo-menu.ps1

.EXAMPLE
    .\demo-menu.ps1 -Attack 1

.EXAMPLE
    .\demo-menu.ps1 -Attack all
#>

[CmdletBinding()]
param(
    [ValidateSet('1', '2', '3', 'all')]
    [string]$Attack
)

# PowerShell 5.1 convierte el stderr de los comandos nativos (los mensajes de
# estado de `docker compose`) en ErrorRecord. Con 'Stop' eso cortaria el script
# aunque Docker haya funcionado; los fallos reales se detectan con
# $LASTEXITCODE y los errores de cmdlets usan -ErrorAction Stop donde importa.
$ErrorActionPreference = 'Continue'

# Ctrl+C: salir con un mensaje claro en vez de dejar el script colgado.
trap [System.Management.Automation.PipelineStoppedException] {
    Write-Host ''
    Write-Host '[!] Demo interrumpida (Ctrl+C).' -ForegroundColor Yellow
    Write-Host '    Los contenedores siguen corriendo. Para apagarlos: docker compose down' -ForegroundColor DarkGray
    exit 130
}

$repoRoot = $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($repoRoot)) {
    $repoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
}
Set-Location -LiteralPath $repoRoot

$AlertsPath = Join-Path $repoRoot 'output\alertas.jsonl'
$DashboardUrl = 'http://localhost:8501'

# Detector indefinido: permite encadenar varios ataques sin que se corte a los 90 s.
$env:NIDS_DURATION = '0'

if ($Attack) {
    $Attack = $Attack.ToLowerInvariant()
}

$script:AttackCatalog = @(
    [pscustomobject]@{
        Id = '1'
        Name = 'SYN flood'
        Perfil = 'neptune'
        Detalle = 'SYNs sin respuesta (serror_rate alto, dst_bytes=0)'
    }
    [pscustomobject]@{
        Id = '2'
        Name = 'Escaneo de puertos'
        Perfil = 'nmap'
        Detalle = 'muchos puertos destino desde un mismo origen'
    }
    [pscustomobject]@{
        Id = '3'
        Name = 'Inundacion HTTP'
        Perfil = 'satan'
        Detalle = 'muchas conexiones con carga y respuesta'
    }
    [pscustomobject]@{
        Id = 'all'
        Name = 'Los tres ataques'
        Perfil = 'neptune + nmap + satan'
        Detalle = 'SYN flood, escaneo de puertos y flood HTTP'
    }
)

function Write-Header {
    param([string]$Title)

    Write-Host ''
    Write-Host ('=' * 64) -ForegroundColor DarkCyan
    Write-Host ('  ' + $Title) -ForegroundColor Cyan
    Write-Host ('=' * 64) -ForegroundColor DarkCyan
}

function Test-Yes {
    param([string]$Answer)

    if ([string]::IsNullOrWhiteSpace($Answer)) {
        return $false
    }
    return ($Answer.Trim() -match '^(s|si|sí|y|yes)$')
}

function Test-Docker {
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
        Write-Host '[!] No se encontró el comando docker.' -ForegroundColor Red
        Write-Host '    Instalá Docker Desktop, abrilo y volvé a intentar.' -ForegroundColor Yellow
        return $false
    }

    & docker info *> $null
    if ($LASTEXITCODE -ne 0) {
        Write-Host '[!] Docker no responde.' -ForegroundColor Red
        Write-Host '    Abrí Docker Desktop y esperá a que el ícono esté en verde.' -ForegroundColor Yellow
        return $false
    }
    return $true
}

function Test-ContainerRunning {
    param([string]$Name)

    $state = & docker inspect --format '{{.State.Running}}' $Name 2>$null
    if ($LASTEXITCODE -ne 0) {
        return $false
    }
    return (($state -join '').Trim() -eq 'true')
}

function Test-DashboardHttp {
    try {
        $response = Invoke-WebRequest -Uri $DashboardUrl -UseBasicParsing -TimeoutSec 3 -ErrorAction Stop
        return ($response.StatusCode -ge 200 -and $response.StatusCode -lt 500)
    } catch {
        return $false
    }
}

function Wait-Dashboard {
    param([int]$TimeoutSeconds = 60)

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        if (Test-DashboardHttp) {
            return $true
        }
        Start-Sleep -Seconds 2
    }
    return (Test-DashboardHttp)
}

function Get-NidsStartedAt {
    $value = & docker inspect --format '{{.State.StartedAt}}' nids-detector 2>$null
    if ($LASTEXITCODE -ne 0) {
        return ''
    }
    return ($value -join '').Trim()
}

function Wait-NidsReady {
    param(
        [int]$TimeoutSeconds = 30,
        [string]$Since = ''
    )

    # Sin un `--since` explicito se usa la ultima vez que arranco el contenedor:
    # si no, los logs viejos ("Capturando en...") hacen creer que ya esta listo
    # cuando en realidad se acaba de reiniciar.
    if ([string]::IsNullOrWhiteSpace($Since)) {
        $Since = Get-NidsStartedAt
    }

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        if (Test-ContainerRunning -Name 'nids-detector') {
            # Sin --tail: la linea de arranque queda al principio y un ataque
            # anterior puede haber generado cientos de lineas de alertas.
            if ([string]::IsNullOrWhiteSpace($Since)) {
                $ready = & docker logs nids-detector 2>$null | Select-String -Pattern 'Capturando en' -Quiet
            } else {
                $ready = & docker logs --since $Since nids-detector 2>$null | Select-String -Pattern 'Capturando en' -Quiet
            }
            if ($ready -eq $true) {
                return $true
            }
        }
        Start-Sleep -Seconds 1
    }
    return $false
}

function Stop-NidsToFlush {
    Write-Host '[..] Volcando alertas pendientes (deteniendo nids de forma limpia)...' -ForegroundColor DarkGray
    & docker compose stop nids *> $null
    if ($LASTEXITCODE -ne 0) {
        Write-Host '[!] No se pudo detener nids para volcar las alertas pendientes.' -ForegroundColor Yellow
        return $false
    }
    return $true
}

function Start-Nids {
    Write-Host '[..] Reiniciando el detector para el proximo ataque...' -ForegroundColor DarkGray
    & docker compose start nids *> $null
    if ($LASTEXITCODE -ne 0) {
        Write-Host '[!] No se pudo reiniciar nids.' -ForegroundColor Yellow
        return $false
    }
    if (-not (Wait-NidsReady -TimeoutSeconds 30)) {
        Write-Host '[!] nids no confirmo que este capturando.' -ForegroundColor Yellow
        return $false
    }
    return $true
}

function Ensure-Base {
    Write-Host '[..] Asegurando victim y nids (detector indefinido)...' -ForegroundColor Cyan
    & docker compose up -d victim nids *> $null
    if ($LASTEXITCODE -ne 0) {
        Write-Host '[!] No se pudieron levantar victim y nids.' -ForegroundColor Red
        Write-Host '    Probá a mano: docker compose up -d victim nids' -ForegroundColor DarkGray
        return $false
    }

    if (-not (Wait-NidsReady -TimeoutSeconds 30)) {
        Write-Host '[!] El NIDS no confirmó que esté capturando; sigo igual.' -ForegroundColor Yellow
    }
    Write-Host '[OK] victim y nids arriba (NIDS_DURATION=0).' -ForegroundColor Green
    return $true
}

function Ensure-Dashboard {
    $running = Test-ContainerRunning -Name 'nids-dashboard'
    $responding = Test-DashboardHttp

    if ($running -and $responding) {
        Write-Host '[OK] El dashboard ya estaba corriendo.' -ForegroundColor Green
    } else {
        Write-Host '[..] Levantando el dashboard...' -ForegroundColor Cyan
    }

    # Idempotente: si ya esta arriba no hace nada; si cambio el compose o un
    # bind mount, lo recrea para que el panel use el codigo nuevo.
    & docker compose up -d dashboard *> $null
    if ($LASTEXITCODE -ne 0) {
        Write-Host '[!] No se pudo levantar el dashboard.' -ForegroundColor Red
        Write-Host '    El menú sigue funcionando sin el panel web.' -ForegroundColor Yellow
        Write-Host '    Probá a mano: docker compose up -d dashboard' -ForegroundColor DarkGray
        return $false
    }

    if (-not (Test-DashboardHttp)) {
        if (Wait-Dashboard -TimeoutSeconds 60) {
            Write-Host '[OK] Dashboard listo.' -ForegroundColor Green
        } else {
            Write-Host '[!] El dashboard no respondió en 60 s.' -ForegroundColor Yellow
            Write-Host '    Revisá: docker compose logs dashboard' -ForegroundColor DarkGray
            return $false
        }
    } elseif (-not $responding) {
        Write-Host '[OK] Dashboard listo.' -ForegroundColor Green
    }

    Write-Host ("    Abrí el panel en: {0}" -f $DashboardUrl) -ForegroundColor Cyan
    return $true
}

function Get-AlertCount {
    param([string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        return 0
    }
    $lines = Get-Content -LiteralPath $Path -ErrorAction SilentlyContinue
    if ($null -eq $lines) {
        return 0
    }
    return @($lines).Count
}

function Get-AttackInfo {
    param([string]$Id)

    foreach ($item in $script:AttackCatalog) {
        if ($item.Id -eq $Id) {
            return $item
        }
    }
    return $null
}

function Show-NewAlerts {
    param(
        [string]$Path,
        [int]$NewCount
    )

    if ($NewCount -le 0) {
        Write-Host '    No se registraron alertas nuevas.' -ForegroundColor Yellow
        Write-Host '    Revisá que nids esté capturando y que el ataque haya durado lo suficiente.' -ForegroundColor DarkGray
        return
    }

    $tailCount = [math]::Min($NewCount, 10)
    $lines = @(Get-Content -LiteralPath $Path -Tail $tailCount -ErrorAction SilentlyContinue)
    Write-Host ("    Últimas {0} alerta(s) nuevas:" -f $tailCount) -ForegroundColor White
    Write-Host ("    {0,-10} {1,-9} {2,7}  {3}" -f 'hora', 'veredicto', 'score', 'detalle') -ForegroundColor DarkGray

    foreach ($line in $lines) {
        if ([string]::IsNullOrWhiteSpace($line)) {
            continue
        }
        try {
            $alert = $line | ConvertFrom-Json -ErrorAction Stop
        } catch {
            continue
        }

        $hour = '--:--:--'
        try {
            $hour = ([datetimeoffset]::Parse([string]$alert.ts)).ToLocalTime().ToString('HH:mm:ss')
        } catch {
            $hour = '--:--:--'
        }

        $label = ([string]$alert.label).ToUpperInvariant()
        $color = 'Green'
        if ($label -eq 'ATAQUE') {
            $color = 'Red'
        }
        $detail = '{0}/{1} flag={2} count={3}' -f $alert.flow.protocol_type, $alert.flow.service, $alert.flow.flag, $alert.flow.count
        Write-Host ("    {0,-10} {1,-9} {2,7:N3}  {3}" -f $hour, $label, [double]$alert.score, $detail) -ForegroundColor $color
    }

    if ($NewCount -gt $tailCount) {
        Write-Host ("    ... y {0} alerta(s) más (ver dashboard)." -f ($NewCount - $tailCount)) -ForegroundColor DarkGray
    }
}

function Invoke-Attack {
    param([string]$Selection)

    $info = Get-AttackInfo -Id $Selection
    if ($null -eq $info) {
        Write-Host ("[!] Ataque desconocido: {0}" -f $Selection) -ForegroundColor Red
        return
    }

    Write-Header ("ATAQUE: {0}" -f $info.Name)
    Write-Host ("  Perfil NSL-KDD : {0}" -f $info.Perfil) -ForegroundColor DarkGray
    Write-Host ("  Qué hace       : {0}" -f $info.Detalle) -ForegroundColor DarkGray

    $before = Get-AlertCount -Path $AlertsPath
    $started = Get-Date

    # stderr de `docker compose` son solo mensajes de estado ("Creating...");
    # el ataque escribe su progreso por stdout y se ve en vivo.
    & docker compose run --rm -e "ATTACK=$Selection" -e "NIDS_WARMUP=0" attacker 2>$null
    $exitCode = $LASTEXITCODE

    $elapsed = ((Get-Date) - $started).TotalSeconds

    # El detector conserva abiertos los flujos que no vieron FIN/RST (un SYN
    # flood entero). El SIGTERM dispara el flush final y los persiste; sin este
    # paso, las alertas del ataque 1 no aparecerian hasta apagar el NIDS.
    [void](Stop-NidsToFlush)

    $after = Get-AlertCount -Path $AlertsPath
    $newAlerts = $after - $before
    if ($newAlerts -lt 0) {
        $newAlerts = 0
    }

    # Se vuelve a levantar para que el proximo ataque tenga detector en vivo.
    [void](Start-Nids)

    if ($exitCode -ne 0) {
        Write-Host ("[!] El atacante terminó con código {0}." -f $exitCode) -ForegroundColor Yellow
    }

    $alertColor = 'Yellow'
    if ($newAlerts -gt 0) {
        $alertColor = 'Green'
    }

    Write-Host ''
    Write-Host '  RESUMEN' -ForegroundColor Cyan
    Write-Host ('  ' + ('-' * 54)) -ForegroundColor DarkGray
    Write-Host ("    Ataque          : {0}" -f $info.Name)
    Write-Host ("    Alertas nuevas  : {0}" -f $newAlerts) -ForegroundColor $alertColor
    Write-Host ("    Duración aprox. : {0:N1} s" -f $elapsed)
    Write-Host ''
    Write-Host '  RESULTADOS' -ForegroundColor Cyan
    Write-Host ('  ' + ('-' * 54)) -ForegroundColor DarkGray
    Show-NewAlerts -Path $AlertsPath -NewCount $newAlerts
    Write-Host ''
    Write-Host ("    Detalle completo: {0}" -f $DashboardUrl) -ForegroundColor Cyan
}

function Show-Menu {
    Write-Header 'NIDS-ML · Menú de demostración'
    Write-Host ("  Dashboard: {0}" -f $DashboardUrl) -ForegroundColor DarkGray
    Write-Host ''
    Write-Host '  1) SYN flood          (perfil neptune: SYNs sin respuesta)'
    Write-Host '  2) Escaneo de puertos (perfil nmap)'
    Write-Host '  3) Inundación HTTP    (perfil satan)'
    Write-Host '  4) Los tres ataques'
    Write-Host '  5) Salir'
    Write-Host ''
}

function Start-Menu {
    if (-not (Ensure-Base)) {
        return
    }
    if (-not (Ensure-Dashboard)) {
        Write-Host '    El menú sigue disponible sin dashboard.' -ForegroundColor Yellow
    }

    while ($true) {
        Show-Menu
        $option = ([string](Read-Host '  Elegí una opción [1-5]')).Trim()

        $selection = ''
        switch ($option) {
            '1' { $selection = '1' }
            '2' { $selection = '2' }
            '3' { $selection = '3' }
            '4' { $selection = 'all' }
            '5' { return }
            default { $selection = '' }
        }

        if ([string]::IsNullOrEmpty($selection)) {
            Write-Host '  Opción inválida. Probá de nuevo.' -ForegroundColor Yellow
            Start-Sleep -Seconds 1
            continue
        }

        Invoke-Attack -Selection $selection

        $again = Read-Host '  ¿Volver al menú? (s/n)'
        if (-not (Test-Yes -Answer $again)) {
            return
        }
    }
}

function Invoke-ShutdownPrompt {
    Write-Host ''
    $answer = Read-Host '  ¿Apagar la demo? (s/n)'

    if (Test-Yes -Answer $answer) {
        Write-Host '[..] Bajando contenedores...' -ForegroundColor Cyan
        & docker compose down *> $null
        if ($LASTEXITCODE -eq 0) {
            Write-Host '[OK] Demo apagada.' -ForegroundColor Green
        } else {
            Write-Host ("[!] docker compose down falló (código {0})." -f $LASTEXITCODE) -ForegroundColor Yellow
        }
        return
    }

    Write-Host '[OK] La demo sigue corriendo.' -ForegroundColor Green
    Write-Host ("    Dashboard: {0}" -f $DashboardUrl) -ForegroundColor Cyan
    Write-Host '    Para apagarla después: docker compose down' -ForegroundColor DarkGray
}

Write-Header 'NIDS-ML · Demo interactiva (solo Docker)'
Write-Host '  Verificá Docker, levantá el detector y lanzá ataques de a uno.' -ForegroundColor DarkGray

if (-not (Test-Docker)) {
    exit 1
}

if ($Attack) {
    Write-Host ("[..] Modo automático: un solo ataque ({0}), sin menú." -f $Attack) -ForegroundColor Cyan
    if (-not (Ensure-Base)) {
        exit 1
    }
    Invoke-Attack -Selection $Attack
    if ((Test-ContainerRunning -Name 'nids-dashboard') -and (Test-DashboardHttp)) {
        Write-Host ("  Dashboard: {0}" -f $DashboardUrl) -ForegroundColor Cyan
    }
    exit 0
}

Start-Menu
Invoke-ShutdownPrompt
