# Vertex Swarm Lab - Track 3: Leaderless Swarm

This repository implements **Vertex Swarm Challenge 2026 - Track 3**.
It demonstrates a decentralized, leaderless swarm that coordinates tasks under contention, remains stable under faults, and produces verifiable coordination proofs without a central orchestrator.

Recommended evaluation environment: Windows 10/11, Python 3.10+, and FoxMQ (for MQTT transport validation).

FoxMQ references:

- Docs: https://docs.tashi.network/resources/foxmq/quick-start-direct
- Releases: https://github.com/tashigg/foxmq/releases

## 60-Second Review

- This project delivers a leaderless Track 3 swarm with deterministic task coordination and verifiable outputs.
- Architecture uses orchestrator compatibility + decentralized agent-side plugin execution.
- Transport backends support `simulated`, `mqtt`, and `official (Rust bridge path)`.
- Core runtime includes plugin registry selection, timeout/retry, inflight backpressure, and task-state tracking.
- Competition-ready path is MQTT: run `powershell -ExecutionPolicy Bypass -File .\start_track3_with_mqtt.ps1`.
- Success criterion is `acceptance_report.json` with all `criteria` fields equal to `true`.

## Architecture Overview

End-to-end flow:

1. Task enters through compatibility entry or SDK dispatch
2. Coordination kernel routes and tracks task state (`pending/routed/running/success/failed`)
3. Agent runtime selects plugin by task metadata and executes with timeout/retry/backpressure controls
4. Results are committed, signed, and exported as verifiable artifacts

Core modules:

- `security_monitor/coordination/`: coordination kernel + decentralized `AgentPluginRuntime`
- `security_monitor/plugins/`: plugin protocol, registry, and built-in business plugins
- `security_monitor/adapters/`: centralized compatibility adapter + external SDK facade
- `security_monitor/integration/`: transport adapter (`simulated`, `mqtt`, `official`)
- `security_monitor/scenarios/`: executable business scenarios (risk control, cross-org alert, etc.)
- `security_monitor/track3/`: submission entry (`main.py`) and acceptance orchestration
- `security_monitor/tests/`: e2e and integration tests

## Feature Coverage

- **Coordination correctness**
  - Single-winner task assignment
  - No double assignment under contention
- **Resilience**
  - Delay/drop fault injection
  - Recovery and state resynchronization
- **Security**
  - Signed envelopes
  - Replay rejection
  - Commit equivocation guard
- **Auditability**
  - Structured event logs
  - Coordination proofs and commit logs
  - Offline verification pipeline
- **Pluginized business execution**
  - Metadata-driven plugin selection
  - Agent-side execution without replacing incumbent orchestrators
- **Runtime controls**
  - Async execution pool
  - Inflight backpressure
  - Plugin timeout + retry
  - Runtime metrics

## Quick Start

### 1) Quick Demo

```bash
python -m security_monitor.track3.main
```

### 2) Acceptance (Simulated Backend)

```bash
python -m security_monitor.track3.main --mode acceptance --foxmq-backend simulated
```

### 3) MQTT Acceptance (Recommended for Competition Runs)

One-click:

```bash
powershell -ExecutionPolicy Bypass -File .\start_track3_with_mqtt.ps1
```

Manual (broker already running):

```bash
python -m security_monitor.track3.main --mode acceptance --foxmq-backend mqtt --foxmq-mqtt-addr 127.0.0.1:1883
```

## E2E and Full Case Execution

### MQTT E2E (Single Test)

```bash
$env:MQTT_E2E="1"; $env:FOXMQ_MQTT_ADDR="127.0.0.1:1884"; python -m unittest security_monitor.tests.test_swarm_track3.Track3SwarmTests.test_mqtt_transport_demo_e2e -v
```

### MQTT Full Track3 Cases

```bash
$env:MQTT_E2E="1"; $env:FOXMQ_MQTT_ADDR="127.0.0.1:1883"; $env:OFFICIAL_E2E="0"; $env:OFFICIAL_MULTI_E2E="0"; python -m unittest security_monitor.tests.test_swarm_track3 -v
```

### Official Bridge E2E (Optional Integration Path)

`official` backend is not the same as MQTT and requires `vertex-rs-bridge` executable.

Single-port:

```bash
$env:VERTEX_RS_BRIDGE_CMD="E:\tools\vertex\vertex-rs-bridge.exe --host 127.0.0.1 --port 1883 --stdio"; $env:OFFICIAL_E2E="1"; python -m unittest security_monitor.tests.test_swarm_track3.Track3SwarmTests.test_official_transport_demo_e2e -v
```

Multi-port:

```bash
$env:VERTEX_RS_BRIDGE_CMD_TEMPLATE="E:\tools\vertex\vertex-rs-bridge.exe --host {host} --port {port} --stdio"; $env:OFFICIAL_MULTI_E2E="1"; python -m unittest security_monitor.tests.test_swarm_track3.Track3SwarmTests.test_official_transport_multi_port_loopback_e2e -v
```

## Outputs and Evidence

Acceptance mode writes:

- `artifacts/<run_name>/acceptance_report.json`
- `artifacts/<run_name>/none|delay|drop/structured_event_log.json`
- `artifacts/<run_name>/none|delay|drop/coordination_proof.json`
- `artifacts/<run_name>/none|delay|drop/commit_log.json`

Pass condition:

- All fields in `criteria` are `true` in `acceptance_report.json`

Reference evidence:

- MQTT hardened acceptance: `artifacts/competition_req_check/acceptance_mqtt_10_hardened/acceptance_report.json`
- Official bridge acceptance: `artifacts/competition_req_check/acceptance_official_10_hardened/acceptance_report.json`
- Simulated hardened baseline: `artifacts/competition_req_check/acceptance_simulated_10_hardened/acceptance_report.json`
