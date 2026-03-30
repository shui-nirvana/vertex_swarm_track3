param(
    [string]$Version = "v0.3.1",
    [string]$ToolsDir = "tools\foxmq",
    [string]$MqttAddr = "127.0.0.1:1883",
    [string]$ClusterAddr = "127.0.0.1:19793",
    [switch]$AllowAnonymousLogin = $true,
    [switch]$NoRun
)

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$runtimeDir = Join-Path (Join-Path $repoRoot $ToolsDir) $Version
$foxmqExe = Join-Path $runtimeDir "foxmq.exe"
$foxmqDataDir = Join-Path $runtimeDir "foxmq.d"
$keyPath = Join-Path $foxmqDataDir "key_0.pem"

if (-not (Test-Path $foxmqExe)) {
    throw "foxmq.exe not found at $foxmqExe. Please manually place FoxMQ $Version at this path."
}

if (-not (Test-Path $foxmqDataDir)) {
    New-Item -ItemType Directory -Force -Path $foxmqDataDir | Out-Null
}

if (-not (Test-Path $keyPath)) {
    Push-Location $runtimeDir
    try {
        & $foxmqExe address-book from-range 127.0.0.1 19793 19793 | Out-Null
    }
    finally {
        Pop-Location
    }
}

$args = @(
    "run",
    "--secret-key-file=$keyPath",
    "--mqtt-addr=$MqttAddr",
    "--cluster-addr=$ClusterAddr"
)

if ($AllowAnonymousLogin) {
    $args += "--allow-anonymous-login"
}

Write-Host "FoxMQ executable: $foxmqExe"
Write-Host "FoxMQ key file:   $keyPath"
Write-Host "MQTT addr:        $MqttAddr"
Write-Host "Cluster addr:     $ClusterAddr"

if (-not $NoRun) {
    & $foxmqExe @args
}
