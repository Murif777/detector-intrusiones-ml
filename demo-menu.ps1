<#
.SYNOPSIS
    Menú interactivo de la demo NIDS-ML. Solo requiere Docker instalado.

.DESCRIPTION
    Levanta victim, nids (con detector indefinido) y dashboard, y permite lanzar
    los ataques de a uno para ver las alertas aparecer en el panel web. También
    puede generar solo tráfico normal o combinar un ataque con tráfico normal.

    El script se ubica solo en la carpeta del repositorio. No usa Python ni uv
    del host: todo corre dentro de los contenedores.

    Al entrar al menú abre el dashboard si no estaba corriendo y muestra el link
    http://localhost:8501. No abre el navegador automáticamente.

    Al terminar cada corrida detiene nids de forma limpia (SIGTERM) para que
    vuelque los flujos que siguen abiertos (por ejemplo, SYNs sin respuesta) y
    recién entonces cuenta los eventos nuevos. Después lo vuelve a levantar,
    siempre con NIDS_DURATION=0, para encadenar la corrida siguiente.

    UMBRAL DE DEMO: el artefacto usa 0.05, pero el tráfico benigno medido puntúa
    ~0.13-0.16. En las corridas que incluyen tráfico normal se setea
    NIDS_THRESHOLD=0.30 (override solo de demo) para no clasificar ese tráfico
    como ataque. Los ataques de la demo puntúan ~0.53-0.80, así que se siguen
    detectando. Las corridas de solo ataque usan el umbral del artefacto.

.PARAMETER Attack
    Corre una sola corrida sin mostrar el menú y termina. Valores: normal, 1,
    2, 3 o all. Es útil para automatizar y para probar el script. En este modo
    no pregunta nada y NO levanta el dashboard (solo victim y nids).

.PARAMETER WithNormal
    Junto con -Attack 1/2/3/all, agrega tráfico normal en paralelo al ataque
    (equivale a la opción 6 del menú). Con -Attack normal no hace falta.

.EXAMPLE
    .\demo-menu.ps1

.EXAMPLE
    .\demo-menu.ps1 -Attack normal

.EXAMPLE
    .\demo-menu.ps1 -Attack 1

.EXAMPLE
    .\demo-menu.ps1 -Attack all -WithNormal
#>

[CmdletBinding()]
param(
    [ValidateSet('normal', '1', '2', '3', 'all')]
    [string]$Attack,

    [switch]$WithNormal
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

# El menú controla el override: arranca sin él para que el NIDS use el artefacto.
Remove-Item Env:NIDS_THRESHOLD -ErrorAction SilentlyContinue

# Umbrales medidos en esta demo:
#   tráfico benigno (24 flujos HTTP): 0.133 - 0.160
#   ataques: SYN 0.797 · escaneo 0.533-0.567 · flood HTTP 0.660
# 0.30 separa benigno de ataque y deja margen para variaciones normales.
$script:DemoThreshold = '0.30'
$script:ArtifactThreshold = '0.05'

if ($Attack) {
    $Attack = $Attack.ToLowerInvariant()
}

$script:AttackCatalog = @(
    [pscustomobject]@{
        Id = 'normal'
        Name = 'Solo tráfico normal'
        Perfil = 'tráfico legítimo'
        Detalle = '30 requests HTTP GET a la víctima (sin ataque)'
    }
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

function Set-NidsThreshold {
    param([string]$Value)

    # Vacío = sin override: el detector usa el umbral del artefacto (0.05).
    if ([string]::IsNullOrWhiteSpace($Value)) {
        Remove-Item Env:NIDS_THRESHOLD -ErrorAction SilentlyContinue
        $shown = $script:ArtifactThreshold
    } else {
        $env:NIDS_THRESHOLD = $Value
        $shown = $Value
    }

    # `up -d` recrea el contenedor solo si cambió el entorno. Es la única forma
    # de que un proceso ya creado lea la variable nueva.
    & docker compose up -d nids *> $null
    if ($LASTEXITCODE -ne 0) {
        Write-Host '[!] No se pudo aplicar el umbral al NIDS.' -ForegroundColor Yellow
        return $false
    }
    if (-not (Wait-NidsReady -TimeoutSeconds 30)) {
        Write-Host '[!] El NIDS no confirmó que esté capturando tras el cambio de umbral.' -ForegroundColor Yellow
        return $false
    }
    Write-Host ("[OK] NIDS con umbral {0}." -f $shown) -ForegroundColor Green
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

function Get-AlertSnapshot {
    param([string]$Path)

    $snapshot = [pscustomobject]@{
        Total   = 0
        Attacks = 0
        Normals = 0
    }
    if (-not (Test-Path -LiteralPath $Path)) {
        return $snapshot
    }
    $lines = Get-Content -LiteralPath $Path -ErrorAction SilentlyContinue
    foreach ($line in @($lines)) {
        if ([string]::IsNullOrWhiteSpace($line)) {
            continue
        }
        $snapshot.Total++
        if ($line -match '"label":"ataque"') {
            $snapshot.Attacks++
        } elseif ($line -match '"label":"normal"') {
            $snapshot.Normals++
        }
    }
    return $snapshot
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

function Show-NewEvents {
    param(
        [string]$Path,
        [int]$NewCount
    )

    if ($NewCount -le 0) {
        Write-Host '    No se registraron eventos nuevos.' -ForegroundColor Yellow
        Write-Host '    Revisá que nids esté capturando y que la corrida haya durado lo suficiente.' -ForegroundColor DarkGray
        return
    }

    $tailCount = [math]::Min($NewCount, 10)
    $lines = @(Get-Content -LiteralPath $Path -Tail $tailCount -ErrorAction SilentlyContinue)
    Write-Host ("    Últimos {0} evento(s) nuevos:" -f $tailCount) -ForegroundColor White
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
        Write-Host ("    ... y {0} evento(s) más (ver dashboard)." -f ($NewCount - $tailCount)) -ForegroundColor DarkGray
    }
}

function Invoke-Attack {
    param(
        [string]$Selection,
        [switch]$WithNormal
    )

    $info = Get-AttackInfo -Id $Selection
    if ($null -eq $info) {
        Write-Host ("[!] Ataque desconocido: {0}" -f $Selection) -ForegroundColor Red
        return
    }

    # ATTACK=normal ya es tráfico normal; con un ataque, -WithNormal agrega
    # tráfico normal en paralelo.
    $soloNormal = ($Selection -eq 'normal')
    $normalEnParalelo = (-not $soloNormal) -and $WithNormal.IsPresent
    $usesNormal = $soloNormal -or $normalEnParalelo

    Write-Header ("CORRIDA: {0}" -f $info.Name)
    Write-Host ("  Perfil NSL-KDD : {0}" -f $info.Perfil) -ForegroundColor DarkGray
    Write-Host ("  Qué hace       : {0}" -f $info.Detalle) -ForegroundColor DarkGray

    if ($usesNormal) {
        Write-Host ("  Umbral         : {0} (demo, NIDS_THRESHOLD)" -f $script:DemoThreshold) -ForegroundColor Yellow
        Write-Host '                   el artefacto usa 0.05; el benigno medido puntúa ~0.13-0.16' -ForegroundColor DarkGray
    } else {
        Write-Host ("  Umbral         : {0} (artefacto)" -f $script:ArtifactThreshold) -ForegroundColor DarkGray
    }
    if ($normalEnParalelo) {
        Write-Host '  Tráfico normal : sí, en paralelo al ataque' -ForegroundColor DarkGray
    } elseif ($soloNormal) {
        Write-Host '  Tráfico normal : sí, sin ataques' -ForegroundColor DarkGray
    }

    # El contenedor NIDS ya está creado: hay que recrearlo para que lea la
    # variable de entorno nueva antes de generar tráfico.
    if ($usesNormal) {
        if (-not (Set-NidsThreshold -Value $script:DemoThreshold)) {
            return
        }
    } else {
        if (-not (Set-NidsThreshold -Value '')) {
            return
        }
    }

    $before = Get-AlertSnapshot -Path $AlertsPath
    $started = Get-Date

    # stderr de `docker compose` son solo mensajes de estado ("Creating...");
    # el ataque escribe su progreso por stdout y se ve en vivo.
    $dockerArgs = @(
        'compose', 'run', '--rm',
        '-e', "ATTACK=$Selection",
        '-e', 'NIDS_WARMUP=0'
    )
    if ($normalEnParalelo) {
        $dockerArgs += @('-e', 'TRAFFIC=normal')
    }
    $dockerArgs += 'attacker'

    & docker @dockerArgs 2>$null
    $exitCode = $LASTEXITCODE

    $elapsed = ((Get-Date) - $started).TotalSeconds

    # El detector conserva abiertos los flujos que no vieron FIN/RST (un SYN
    # flood entero). El SIGTERM dispara el flush final y los persiste; sin este
    # paso, los eventos del ataque 1 no aparecerian hasta apagar el NIDS.
    [void](Stop-NidsToFlush)

    $after = Get-AlertSnapshot -Path $AlertsPath
    $newAttacks = $after.Attacks - $before.Attacks
    if ($newAttacks -lt 0) {
        $newAttacks = 0
    }
    $newNormals = $after.Normals - $before.Normals
    if ($newNormals -lt 0) {
        $newNormals = 0
    }
    $newEvents = $newAttacks + $newNormals

    # Se vuelve a levantar para que la proxima corrida tenga detector en vivo.
    [void](Start-Nids)

    if ($exitCode -ne 0) {
        Write-Host ("[!] El atacante terminó con código {0}." -f $exitCode) -ForegroundColor Yellow
    }

    $attackColor = 'Yellow'
    if ($newAttacks -gt 0) {
        $attackColor = 'Green'
    }
    $normalColor = 'Yellow'
    if ($newNormals -gt 0) {
        $normalColor = 'Green'
    }

    Write-Host ''
    Write-Host '  RESUMEN' -ForegroundColor Cyan
    Write-Host ('  ' + ('-' * 54)) -ForegroundColor DarkGray
    Write-Host ("    Corrida                  : {0}" -f $info.Name)
    Write-Host ("    Alertas nuevas (ataques) : {0}" -f $newAttacks) -ForegroundColor $attackColor
    Write-Host ("    Flujos normales nuevos   : {0}" -f $newNormals) -ForegroundColor $normalColor
    Write-Host ("    Duración aprox.          : {0:N1} s" -f $elapsed)
    Write-Host ''
    Write-Host '  RESULTADOS' -ForegroundColor Cyan
    Write-Host ('  ' + ('-' * 54)) -ForegroundColor DarkGray
    Show-NewEvents -Path $AlertsPath -NewCount $newEvents
    Write-Host ''
    Write-Host ("    Detalle completo: {0}" -f $DashboardUrl) -ForegroundColor Cyan
}

function Show-Menu {
    Write-Header 'NIDS-ML · Menú de demostración'
    Write-Host ("  Dashboard: {0}" -f $DashboardUrl) -ForegroundColor DarkGray
    Write-Host ''
    Write-Host '  1) Solo tráfico normal'
    Write-Host '  2) SYN flood                 (perfil neptune: SYNs sin respuesta)'
    Write-Host '  3) Escaneo de puertos        (perfil nmap)'
    Write-Host '  4) Inundación HTTP           (perfil satan)'
    Write-Host '  5) Los tres ataques'
    Write-Host '  6) Ataque + tráfico normal   (pregunta cuál ataque: 1/2/3/all)'
    Write-Host '  7) Salir'
    Write-Host ''
    Write-Host '  Nota: las corridas con tráfico normal usan umbral de demo 0.30' -ForegroundColor DarkGray
    Write-Host '        (el artefacto usa 0.05; el benigno medido puntúa ~0.13-0.16).' -ForegroundColor DarkGray
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
        $option = ([string](Read-Host '  Elegí una opción [1-7]')).Trim()

        $selection = ''
        $withNormal = $false
        switch ($option) {
            '1' { $selection = 'normal' }
            '2' { $selection = '1' }
            '3' { $selection = '2' }
            '4' { $selection = '3' }
            '5' { $selection = 'all' }
            '6' {
                $which = ([string](Read-Host '  ¿Qué ataque? [1=SYN flood, 2=escaneo, 3=HTTP flood, all=los tres]')).Trim().ToLowerInvariant()
                if ($which -in @('1', '2', '3', 'all')) {
                    $selection = $which
                    $withNormal = $true
                }
            }
            '7' { return }
            default { $selection = '' }
        }

        if ([string]::IsNullOrEmpty($selection)) {
            Write-Host '  Opción inválida. Probá de nuevo.' -ForegroundColor Yellow
            Start-Sleep -Seconds 1
            continue
        }

        if ($withNormal) {
            Invoke-Attack -Selection $selection -WithNormal
        } else {
            Invoke-Attack -Selection $selection
        }

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
Write-Host '  Verificá Docker, levantá el detector y lanzá tráfico normal o ataques.' -ForegroundColor DarkGray

if (-not (Test-Docker)) {
    exit 1
}

if ($Attack) {
    $mode = 'una corrida'
    if ($WithNormal -and $Attack -ne 'normal') {
        $mode = 'ataque + tráfico normal'
    }
    Write-Host ("[..] Modo automático: {0} ({1}), sin menú." -f $mode, $Attack) -ForegroundColor Cyan
    if (-not (Ensure-Base)) {
        exit 1
    }
    if ($WithNormal) {
        Invoke-Attack -Selection $Attack -WithNormal
    } else {
        Invoke-Attack -Selection $Attack
    }
    if ((Test-ContainerRunning -Name 'nids-dashboard') -and (Test-DashboardHttp)) {
        Write-Host ("  Dashboard: {0}" -f $DashboardUrl) -ForegroundColor Cyan
    }
    exit 0
}

Start-Menu
Invoke-ShutdownPrompt
