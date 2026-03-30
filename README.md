# Vertex Swarm Track3 (Leaderless Swarm)

This repository is the current implementation of Vertex Swarm Challenge 2026 Track3. It focuses on:

- Coordinating Scout / Guardian / Verifier without a central orchestrator
- Maintaining recoverability and verifiability under fault scenarios (delay/drop)
- Producing auditable coordination artifacts (Vertex consensus proof, multisig output, structured event logs)

The primary execution path is **FoxMQ MQTT clustered mode** (Windows + Python 3.10+).

## Current Capabilities

- Decentralized task coordination: publish, bidding, role assignment, execution, and verification through inter-agent messaging
- Vertex consensus in production path: DAG event ordering with `ordered_event_ids` and proof checks
- Lattice-aligned checks: discovery, authorized participants, independent validation, reputation routing, failover
- Security and auditability: signature verification, anti-replay, anti-forgery, equivocation guard
- Multi-process operation: independent agent processes + FoxMQ broker for end-to-end mission completion

## Project Structure

- `security_monitor/track3/`: Track3 entry and protocol flow (`main.py`, `protocol.py`)
- `security_monitor/swarm/`: node model, messages, consensus, fault injection, Vertex engine
- `security_monitor/coordination/`: coordination kernel and runtime
- `security_monitor/roles/`: Scout / Guardian / Verifier role implementations
- `security_monitor/integration/`: FoxMQ and settlement integrations
- `security_monitor/tests/`: Track3 tests (including multi-process scenarios)
- `start_foxmq.ps1`: local FoxMQ bootstrap script
- `start_track3_with_mqtt.ps1`: one-click broker + agents + mission launcher

## Requirements

- Windows 10/11 (PowerShell 5+)
- Python 3.10+
- Local FoxMQ binary (default path: `tools/foxmq/v0.3.1/foxmq.exe`)

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

### 2) One-click Run (Recommended)

Run agent bootstrap mission (auto-starts guardian / verifier, scout performs bootstrap):

```powershell
powershell -ExecutionPolicy Bypass -File .\start_track3_with_mqtt.ps1 -Mode agent-bootstrap
```

Run internal acceptance bundle (none/delay/drop scenarios):

```powershell
powershell -ExecutionPolicy Bypass -File .\start_track3_with_mqtt.ps1 -Mode internal-acceptance
```

### 3) Manual Multi-process Run (4 terminals)

Start 2 resident agents first:

```powershell
python -m security_monitor.track3.main --mode agent-process --agent-id agent-guardian --foxmq-backend mqtt --foxmq-mqtt-addr 127.0.0.1:1883 --run-id demo001 --topic-namespace run-demo001
python -m security_monitor.track3.main --mode agent-process --agent-id agent-verifier --foxmq-backend mqtt --foxmq-mqtt-addr 127.0.0.1:1883 --run-id demo001 --topic-namespace run-demo001
```

Then start scout bootstrap mission (auto-exits on completion and writes mission report):

```powershell
python -m security_monitor.track3.main --mode agent-process --agent-id agent-scout --foxmq-backend mqtt --foxmq-mqtt-addr 127.0.0.1:1883 --run-id demo001 --topic-namespace run-demo001 --output-dir artifacts/track3 --bootstrap-mission --exit-on-mission-complete --bootstrap-ready-timeout-seconds 30 --bootstrap-wait-timeout-seconds 60
```

## CLI Modes (`security_monitor.track3.main`)

- `--mode internal-single`: single-process demo with `--fault none|delay|drop`
- `--mode internal-acceptance`: runs acceptance bundle and writes `acceptance_report.json`
- `--mode agent-process`: starts an independent agent process, optionally with `--bootstrap-mission`

Common arguments:

- `--foxmq-mqtt-addr 127.0.0.1:1883`
- `--run-id <id>` with `--topic-namespace run-<id>` (recommended as a pair)
- `--output-dir <dir>`
- `--agent-capabilities scout,guardian,verifier`

## Outputs and Pass Criteria

### internal-single / internal-acceptance

- `artifacts/<run>/none|delay|drop/structured_event_log.json`
- `artifacts/<run>/none|delay|drop/coordination_proof.json`
- `artifacts/<run>/none|delay|drop/commit_log.json`
- `artifacts/<run>/acceptance_report.json`

Pass condition:

- All entries in `criteria` are `true` in `acceptance_report.json`

### agent bootstrap mission

- `artifacts/<run>/multiprocess_mission_record.json`

Key fields:

- `all_success`
- `role_identity_assignments`
- `coordination_proof` (including `proof_payload`, `signatures/multisig_summary`)
- `proof_checks`
- `competition_alignment`
- `lattice`
- `standard_metrics`

Pass condition:

- `all_success=true` in `multiprocess_mission_record.json`

## Testing and Quality Gates

Set MQTT address first:

```powershell
$env:FOXMQ_MQTT_ADDR="127.0.0.1:1883"
```

Run Track3 tests:

```powershell
python -m unittest security_monitor.tests.test_swarm_track3 -v
```

Run Vertex consensus focused tests:

```powershell
python -m unittest security_monitor.tests.test_vertex_consensus -v
```

Run lint/type check:

```powershell
python -m ruff check .
python -m mypy security_monitor
```

## FAQ

- FoxMQ is not reachable
  - Ensure `start_foxmq.ps1` is running and `127.0.0.1:1883` is reachable
- Multi-process mission fails with `all_success=false`
  - Inspect `failure_reason`, `readiness`, and `proof_checks` in `multiprocess_mission_record.json`
- `python -m mypy` fails because of missing `agent_tmp`
  - Use the repository-stable command: `python -m mypy security_monitor`
