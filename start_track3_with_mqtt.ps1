param(
    [string]$Version = "v0.3.1",
    [string]$ToolsDir = "tools\foxmq",
    [string]$MqttAddr = "127.0.0.1:1883",
    [string]$ClusterAddr = "127.0.0.1:19793",
    [int]$Workers = 2,
    [string]$OutputDir = "artifacts/agent_bootstrap_mqtt_latest",
    [ValidateSet("agent-bootstrap", "internal-acceptance")]
    [string]$Mode = "agent-bootstrap",
    [string]$RunId = "",
    [switch]$KeepFoxMQ,
    [switch]$KeepAgents,
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
    "-ToolsDir", $ToolsDir,
    "-MqttAddr", $MqttAddr,
    "-ClusterAddr", $ClusterAddr,
    "-NoRun"
)
if ($AllowAnonymousLogin) {
    $setupArgs += "-AllowAnonymousLogin"
}

& powershell @setupArgs

$runtimeDir = Join-Path (Join-Path $repoRoot $ToolsDir) $Version
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
$agentProcesses = @()
$resolvedRunId = $RunId
if ([string]::IsNullOrWhiteSpace($resolvedRunId)) {
    $resolvedRunId = [Guid]::NewGuid().ToString("N").Substring(0, 12)
}
$topicNamespace = "run-$resolvedRunId"

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
        if ($Mode -eq "internal-acceptance") {
            & python -m security_monitor.track3.main --mode internal-acceptance --workers $Workers --foxmq-backend mqtt --foxmq-mqtt-addr $MqttAddr --output-dir $OutputDir
            if ($LASTEXITCODE -ne 0) {
                throw "Track3 internal acceptance failed with exit code $LASTEXITCODE"
            }
        }
        else {
            $agentProcesses += Start-Process -FilePath "python" -ArgumentList @("-m", "security_monitor.track3.main", "--mode", "agent-process", "--agent-id", "agent-guardian", "--foxmq-backend", "mqtt", "--foxmq-mqtt-addr", $MqttAddr, "--run-id", $resolvedRunId, "--topic-namespace", $topicNamespace) -WorkingDirectory $repoRoot -PassThru
            $agentProcesses += Start-Process -FilePath "python" -ArgumentList @("-m", "security_monitor.track3.main", "--mode", "agent-process", "--agent-id", "agent-verifier", "--foxmq-backend", "mqtt", "--foxmq-mqtt-addr", $MqttAddr, "--run-id", $resolvedRunId, "--topic-namespace", $topicNamespace) -WorkingDirectory $repoRoot -PassThru
            Start-Sleep -Seconds 2
            foreach ($proc in $agentProcesses) {
                if ($null -ne $proc -and $proc.HasExited) {
                    throw "agent process exited unexpectedly before mission run: pid=$($proc.Id)"
                }
            }
            $bootstrap = Start-Process -FilePath "python" -ArgumentList @("-m", "security_monitor.track3.main", "--mode", "agent-process", "--agent-id", "agent-scout", "--foxmq-backend", "mqtt", "--foxmq-mqtt-addr", $MqttAddr, "--run-id", $resolvedRunId, "--topic-namespace", $topicNamespace, "--output-dir", $OutputDir, "--bootstrap-mission", "--exit-on-mission-complete", "--bootstrap-ready-timeout-seconds", "30", "--bootstrap-wait-timeout-seconds", "60") -WorkingDirectory $repoRoot -PassThru -Wait
            if ($bootstrap.ExitCode -ne 0) {
                throw "Track3 agent bootstrap mission failed with exit code $($bootstrap.ExitCode)"
            }
        }
    }
    finally {
        Pop-Location
    }
}
finally {
    if (-not $KeepAgents) {
        foreach ($proc in $agentProcesses) {
            if ($null -ne $proc -and -not $proc.HasExited) {
                Stop-Process -Id $proc.Id -Force
            }
        }
    }
    else {
        foreach ($proc in $agentProcesses) {
            if ($null -ne $proc) {
                Write-Host "Agent remains running with PID $($proc.Id)"
            }
        }
    }
    if (-not $KeepFoxMQ) {
        if ($null -ne $foxmqProcess -and -not $foxmqProcess.HasExited) {
            Stop-Process -Id $foxmqProcess.Id -Force
        }
    }
    else {
        Write-Host "FoxMQ remains running with PID $($foxmqProcess.Id)"
    }
}
