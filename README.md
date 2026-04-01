# Vertex Swarm Track3

Leaderless multi-agent coordination runtime for Vertex Swarm Challenge 2026 Track3.

The system runs Scout / Guardian / Verifier style business flows over FoxMQ (MQTT), executes decentralized role negotiation, and produces auditable mission artifacts.

## What This Project Does

- Runs independent agent processes without a central orchestrator.
- Negotiates role ownership and task execution through coordination primitives (intent/claim/stage/complete).
- Executes end-to-end business pipelines (currently focused on `threat_intel` in the panel flow).
- Produces proof-oriented artifacts for replay, validation, and operations debugging.
- Provides a real-time timeline panel for mission and runtime event inspection.

## Current Runtime Model

- Transport: FoxMQ MQTT (`127.0.0.1:1883` by default)
- Cluster mode: multiple agent processes in one run namespace (`run-<run_id>`)
- Core path:
  1. mission start
  2. role negotiation and claims
  3. stage execution (scout -> guardian -> verifier)
  4. mission completion

## Repository Layout

- `security_monitor/track3/`
  - Entry/runtime flow: `main.py`
  - Internal protocol/demo helpers: `protocol.py`
- `security_monitor/panel/`
  - Timeline panel server and rendering logic: `server.py`
- `security_monitor/coordination/`
  - Coordination kernel/runtime integration
- `security_monitor/swarm/`
  - Consensus, message model, and related swarm mechanics
- `security_monitor/roles/`
  - Role implementations
- `security_monitor/plugins/`
  - Business task plugins (including threat intel processing)
- `security_monitor/tests/`
  - Unit/integration tests for runtime, panel, consensus, and flows
- `start_foxmq.ps1`
  - Local FoxMQ bootstrap script
- `start_track3_with_mqtt.ps1`
  - Main one-command launcher for test/runtime modes

## Requirements

- Windows 10/11
- PowerShell 5+
- Python 3.10+
- Local FoxMQ binary (default expected under `tools/foxmq/v0.3.1/foxmq.exe`)

FoxMQ references:

- Docs: https://docs.tashi.network/resources/foxmq/quick-start-direct
- Releases: https://github.com/tashigg/foxmq/releases

## Quick Start

### 1) Start FoxMQ

```powershell
powershell -ExecutionPolicy Bypass -File .\start_foxmq.ps1
```

Default listeners:

- MQTT: `127.0.0.1:1883`
- Cluster: `127.0.0.1:19793`

### 2) Start Runtime Cluster + Panel

```powershell
powershell -ExecutionPolicy Bypass -File .\start_track3_with_mqtt.ps1 -Mode runtime-cluster -RuntimeClusterAgents 5 -PanelPort 8787 -RunId demo-track3
```

Panel URL:

- `http://127.0.0.1:8787/`

### 3) Bootstrap Mission (single command flow)

```powershell
powershell -ExecutionPolicy Bypass -File .\start_track3_with_mqtt.ps1 -Mode agent-bootstrap
```

## Launcher Modes (`start_track3_with_mqtt.ps1`)

- `agent-bootstrap`
- `internal-acceptance`
- `tests-unit`
- `tests-e2e`
- `tests-all`
- `tests-all-cluster-strict`
- `runtime-single`
- `runtime-cluster`

Common useful flags:

- `-RunId <id>`
- `-PanelPort <port>`
- `-RuntimeClusterAgents <n>` (runtime-cluster requires at least 3)
- `-MqttAddr <host:port>`

## Python Entry Modes (`security_monitor.track3.main`)

- `--mode internal-single`
- `--mode internal-acceptance`
- `--mode agent-process`

Common args:

- `--foxmq-backend mqtt`
- `--foxmq-mqtt-addr 127.0.0.1:1883`
- `--run-id <id>`
- `--topic-namespace run-<id>`
- `--output-dir <dir>`
- `--agent-capabilities scout,guardian,verifier`

## Main Artifacts

- `artifacts/.../structured_event_log.json`
- `artifacts/.../coordination_proof.json`
- `artifacts/.../commit_log.json`
- `artifacts/.../acceptance_report.json`
- `artifacts/.../multiprocess_mission_record.json`

Key fields to inspect in mission record:

- `all_success`
- `role_identity_assignments`
- `steps`
- `coordination_proof`
- `proof_checks`
- `standard_metrics`
- `business_flow_log`

## Threat Intel Timeline Semantics (Panel)

The panel currently maps threat intel execution into business semantics:

- `S0` Lead Intake
- `S1` Source Scoring and Conflict Resolution
- `S2` ATT&CK/Kill-Chain Mapping
- `S3` Playbook Planning and Execution
- `S4` Monitoring Window and Secondary Verification
- `S5` Completion/Rollback

The business chain lines and detail text are now fully English in the panel.

## Testing and Quality Gates

Set MQTT env when needed:

```powershell
$env:FOXMQ_MQTT_ADDR="127.0.0.1:1883"
```

Run tests:

```powershell
python -m unittest security_monitor.tests.test_swarm_track3 -v
python -m unittest security_monitor.tests.test_vertex_consensus -v
python -m unittest security_monitor.tests.test_panel_server -v
```

Run lint and typing:

```powershell
python -m ruff check .
python -m mypy security_monitor
```

## Troubleshooting

- FoxMQ not reachable:
  - Ensure `start_foxmq.ps1` is running
  - Ensure `127.0.0.1:1883` is reachable
- Mission not completing:
  - Check `all_success`, `steps`, and `proof_checks` in mission record
  - Review panel runtime events for stage failures
- Type-check mismatch:
  - Use `python -m mypy security_monitor` from repo root
