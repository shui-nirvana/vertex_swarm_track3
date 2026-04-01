param(
    [string]$Version = "v0.3.1",
    [string]$ToolsDir = "tools\foxmq",
    [string]$MqttAddr = "127.0.0.1:1883",
    [string]$ClusterAddr = "127.0.0.1:19793",
    [int]$Workers = 2,
    [string]$OutputDir = "artifacts/agent_bootstrap_mqtt_latest",
    [ValidateSet("agent-bootstrap", "internal-acceptance", "tests-unit", "tests-e2e", "tests-all", "tests-all-cluster-strict", "runtime-single", "runtime-cluster")]
    [string]$Mode = "agent-bootstrap",
    [string]$RunId = "",
    [switch]$KeepFoxMQ,
    [switch]$KeepAgents,
    [switch]$AllowAnonymousLogin = $true,
    [int]$PanelPort = 8787,
    [switch]$EnablePanel = $true,
    [int]$RuntimeClusterAgents = 5
)

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$requiresFoxMQ = @("agent-bootstrap", "internal-acceptance", "tests-e2e", "tests-all", "tests-all-cluster-strict", "runtime-single", "runtime-cluster") -contains $Mode
$foxmqProcess = $null
$agentProcesses = @()
$panelProcess = $null
$resolvedRunId = $RunId
if ([string]::IsNullOrWhiteSpace($resolvedRunId)) {
    $resolvedRunId = [Guid]::NewGuid().ToString("N").Substring(0, 12)
}
$topicNamespace = "run-$resolvedRunId"

function Invoke-CheckedCommand {
    param(
        [string[]]$PythonArgs,
        [string]$FailureMessage
    )
    & python @PythonArgs
    if ($LASTEXITCODE -ne 0) {
        throw "$FailureMessage (exit code $LASTEXITCODE)"
    }
}

function Invoke-StrictUnittestModules {
    param(
        [string[]]$Modules,
        [string]$FailureMessage
    )
    & python -c "import sys,unittest;suite=unittest.defaultTestLoader.loadTestsFromNames(sys.argv[1:]);result=unittest.TextTestRunner(verbosity=2).run(suite);sys.exit(0 if result.wasSuccessful() and len(result.skipped)==0 else 1)" @Modules
    if ($LASTEXITCODE -ne 0) {
        throw "$FailureMessage (strict mode requires zero skipped tests)"
    }
}

function Invoke-StrictUnittestDiscover {
    param(
        [string]$StartDir,
        [string]$Pattern,
        [string]$FailureMessage
    )
    & python -c "import sys,unittest;start_dir=sys.argv[1];pattern=sys.argv[2];suite=unittest.defaultTestLoader.discover(start_dir=start_dir,pattern=pattern);result=unittest.TextTestRunner(verbosity=2).run(suite);sys.exit(0 if result.wasSuccessful() and len(result.skipped)==0 else 1)" $StartDir $Pattern
    if ($LASTEXITCODE -ne 0) {
        throw "$FailureMessage (strict mode requires zero skipped tests)"
    }
}

function Start-FoxMQ {
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
    $started = Start-Process -FilePath $foxmqExe -ArgumentList $foxmqArgs -WorkingDirectory $runtimeDir -PassThru
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
    return $started
}

try {
    if ($requiresFoxMQ) {
        $foxmqProcess = Start-FoxMQ
    }
    Push-Location $repoRoot
    try {
        if ($Mode -eq "tests-unit") {
            Invoke-CheckedCommand -PythonArgs @("-m", "unittest", "discover", "-s", "security_monitor/tests", "-p", "test_*.py") -FailureMessage "Unit test discovery failed"
        }
        elseif ($Mode -eq "tests-e2e") {
            $env:MQTT_E2E = "1"
            $env:FOXMQ_MQTT_ADDR = $MqttAddr
            $env:MULTIPROCESS_E2E = "1"
            $env:MULTIPROCESS_RECOVERY_E2E = "1"
            Invoke-StrictUnittestModules -Modules @("security_monitor.tests.test_coordination_layers", "security_monitor.tests.test_swarm_track3") -FailureMessage "MQTT E2E tests failed"
        }
        elseif ($Mode -eq "tests-all") {
            Invoke-CheckedCommand -PythonArgs @("-m", "unittest", "discover", "-s", "security_monitor/tests", "-p", "test_*.py") -FailureMessage "Unit test discovery failed"
            $env:MQTT_E2E = "1"
            $env:FOXMQ_MQTT_ADDR = $MqttAddr
            $env:MULTIPROCESS_E2E = "1"
            $env:MULTIPROCESS_RECOVERY_E2E = "1"
            Invoke-StrictUnittestModules -Modules @("security_monitor.tests.test_coordination_layers", "security_monitor.tests.test_swarm_track3") -FailureMessage "MQTT E2E tests failed"
        }
        elseif ($Mode -eq "tests-all-cluster-strict") {
            $env:MQTT_E2E = "1"
            $env:FOXMQ_MQTT_ADDR = $MqttAddr
            $env:MULTIPROCESS_E2E = "1"
            $env:MULTIPROCESS_RECOVERY_E2E = "1"
            Invoke-StrictUnittestDiscover -StartDir "security_monitor/tests" -Pattern "test_*.py" -FailureMessage "Cluster strict full discovery failed"
        }
        elseif ($Mode -eq "internal-acceptance") {
            Invoke-CheckedCommand -PythonArgs @("-m", "security_monitor.track3.main", "--mode", "internal-acceptance", "--workers", "$Workers", "--foxmq-backend", "mqtt", "--foxmq-mqtt-addr", $MqttAddr, "--output-dir", $OutputDir) -FailureMessage "Track3 internal acceptance failed"
        }
        elseif ($Mode -eq "runtime-single") {
            $singleAgentId = "agent-local"
            if ($EnablePanel) {
                $panelProcess = Start-Process -FilePath "python" -ArgumentList @("-m", "security_monitor.panel.server", "--host", "127.0.0.1", "--port", "$PanelPort", "--artifacts-dir", "artifacts", "--local-agent-id", $singleAgentId, "--run-id", $resolvedRunId, "--topic-namespace", $topicNamespace, "--foxmq-mqtt-addr", $MqttAddr) -WorkingDirectory $repoRoot -PassThru
                Start-Sleep -Milliseconds 500
            }
            $agentProcesses += Start-Process -FilePath "python" -ArgumentList @("-m", "security_monitor.track3.main", "--mode", "agent-process", "--agent-id", $singleAgentId, "--foxmq-backend", "mqtt", "--foxmq-mqtt-addr", $MqttAddr, "--run-id", $resolvedRunId, "--topic-namespace", $topicNamespace, "--output-dir", $OutputDir) -WorkingDirectory $repoRoot -PassThru
            Write-Host "Runtime single mode started. run_id=$resolvedRunId namespace=$topicNamespace"
            Write-Host "Agent PID: $($agentProcesses[0].Id)"
            if ($null -ne $panelProcess) {
                Write-Host "Panel PID: $($panelProcess.Id) http://127.0.0.1:$PanelPort/"
                Start-Process "http://127.0.0.1:$PanelPort/" | Out-Null
            }
            while ($true) { Start-Sleep -Seconds 5 }
        }
        elseif ($Mode -eq "runtime-cluster") {
            if ($RuntimeClusterAgents -lt 3) {
                throw "runtime-cluster mode requires at least 3 agents (current: $RuntimeClusterAgents)"
            }
            $runtimeAgentIds = @("agent-scout", "agent-guardian", "agent-verifier")
            if ($RuntimeClusterAgents -gt 3) {
                for ($i = 4; $i -le $RuntimeClusterAgents; $i++) {
                    $runtimeAgentIds += "agent-worker-$i"
                }
            }
            if ($EnablePanel) {
                $panelProcess = Start-Process -FilePath "python" -ArgumentList @("-m", "security_monitor.panel.server", "--host", "127.0.0.1", "--port", "$PanelPort", "--artifacts-dir", "artifacts", "--run-id", $resolvedRunId, "--topic-namespace", $topicNamespace, "--foxmq-mqtt-addr", $MqttAddr) -WorkingDirectory $repoRoot -PassThru
                Start-Sleep -Milliseconds 500
            }
            foreach ($agentId in $runtimeAgentIds) {
                $agentProcesses += Start-Process -FilePath "python" -ArgumentList @("-m", "security_monitor.track3.main", "--mode", "agent-process", "--agent-id", $agentId, "--foxmq-backend", "mqtt", "--foxmq-mqtt-addr", $MqttAddr, "--run-id", $resolvedRunId, "--topic-namespace", $topicNamespace, "--output-dir", $OutputDir) -WorkingDirectory $repoRoot -PassThru
            }
            Write-Host "Runtime cluster mode started. run_id=$resolvedRunId namespace=$topicNamespace agents=$($runtimeAgentIds.Count)"
            foreach ($proc in $agentProcesses) {
                Write-Host "Agent PID: $($proc.Id)"
            }
            if ($null -ne $panelProcess) {
                Write-Host "Panel PID: $($panelProcess.Id) http://127.0.0.1:$PanelPort/"
                Start-Process "http://127.0.0.1:$PanelPort/" | Out-Null
            }
            while ($true) { Start-Sleep -Seconds 5 }
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
        if ($null -ne $panelProcess -and -not $panelProcess.HasExited) {
            Stop-Process -Id $panelProcess.Id -Force
        }
    }
    else {
        foreach ($proc in $agentProcesses) {
            if ($null -ne $proc) {
                Write-Host "Agent remains running with PID $($proc.Id)"
            }
        }
        if ($null -ne $panelProcess) {
            Write-Host "Panel remains running with PID $($panelProcess.Id)"
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
