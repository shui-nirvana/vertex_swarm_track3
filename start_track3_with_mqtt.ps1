param(
    [string]$Version = "v0.3.0",
    [string]$InstallDir = "artifacts\foxmq_runtime",
    [string]$MqttAddr = "127.0.0.1:1883",
    [string]$ClusterAddr = "127.0.0.1:19793",
    [int]$Workers = 2,
    [string]$OutputDir = "artifacts/acceptance_mqtt_latest",
    [switch]$KeepFoxMQ,
    [switch]$AllowAnonymousLogin = $true
)

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$startFoxmqScript = Join-Path $repoRoot "start_foxmq.ps1"
if (-not (Test-Path $startFoxmqScript)) {
    throw "start_foxmq.ps1 not found at $startFoxmqScript"
}

$setupArgs = @(
    "-ExecutionPolicy", "Bypass",
    "-File", $startFoxmqScript,
    "-Version", $Version,
    "-InstallDir", $InstallDir,
    "-MqttAddr", $MqttAddr,
    "-ClusterAddr", $ClusterAddr,
    "-NoRun"
)
if ($AllowAnonymousLogin) {
    $setupArgs += "-AllowAnonymousLogin"
}

& powershell @setupArgs

$runtimeDir = Join-Path $repoRoot $InstallDir
$foxmqExe = Join-Path $runtimeDir "foxmq.exe"
$keyPath = Join-Path $runtimeDir "foxmq.d\key_0.pem"

if (-not (Test-Path $foxmqExe)) {
    throw "foxmq.exe not found at $foxmqExe"
}
if (-not (Test-Path $keyPath)) {
    throw "FoxMQ key not found at $keyPath"
}

$foxmqArgs = @(
    "run",
    "--secret-key-file=$keyPath",
    "--mqtt-addr=$MqttAddr",
    "--cluster-addr=$ClusterAddr"
)
if ($AllowAnonymousLogin) {
    $foxmqArgs += "--allow-anonymous-login"
}

$foxmqProcess = Start-Process -FilePath $foxmqExe -ArgumentList $foxmqArgs -WorkingDirectory $runtimeDir -PassThru

try {
    $parts = $MqttAddr.Split(":")
    if ($parts.Count -ne 2) {
        throw "MqttAddr must be host:port, got $MqttAddr"
    }
    $mqttHost = $parts[0]
    $port = [int]$parts[1]

    $ready = $false
    for ($i = 0; $i -lt 30; $i++) {
        try {
            $client = New-Object System.Net.Sockets.TcpClient
            $client.Connect($mqttHost, $port)
            $client.Close()
            $ready = $true
            break
        }
        catch {
            Start-Sleep -Milliseconds 500
        }
    }
    if (-not $ready) {
        throw "FoxMQ did not become reachable at $MqttAddr"
    }

    Push-Location $repoRoot
    try {
        & python -m security_monitor.track3.main --mode acceptance --workers $Workers --foxmq-backend mqtt --foxmq-mqtt-addr $MqttAddr --output-dir $OutputDir
        if ($LASTEXITCODE -ne 0) {
            throw "Track3 acceptance failed with exit code $LASTEXITCODE"
        }
    }
    finally {
        Pop-Location
    }
}
finally {
    if (-not $KeepFoxMQ) {
        if ($null -ne $foxmqProcess -and -not $foxmqProcess.HasExited) {
            Stop-Process -Id $foxmqProcess.Id -Force
        }
    }
    else {
        Write-Host "FoxMQ remains running with PID $($foxmqProcess.Id)"
    }
}
