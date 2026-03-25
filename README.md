# Vertex Swarm Lab - Track 3: Leaderless Swarm

This repository implements **Vertex Swarm Challenge 2026 - Track 3**.
It demonstrates a decentralized, leaderless swarm that coordinates tasks under contention, remains stable under faults, and produces verifiable coordination proofs without a central orchestrator.

Recommended evaluation environment: Windows 10/11, Python 3.10+, and FoxMQ (for MQTT transport validation).

FoxMQ references:

- Docs: https://docs.tashi.network/resources/foxmq/quick-start-direct
- Releases: https://github.com/tashigg/foxmq/releases

## Project Status

- [x] Core Swarm Protocol (Discover, Bid, Commit, Execute, Verify)
- [x] Leaderless Deterministic Consensus with single-winner and no-double-assignment guarantees
- [x] Fault Resilience (delay/drop + partition/restart recovery with hive-memory resync)
- [x] Verifiable Coordination Proofs (hash chain + anchor + offline verification via `verify_proof_document`)
- [x] Security Hardening (signed envelopes, replay rejection, commit equivocation guard)
- [x] Multi-Transport Execution (simulated, MQTT, official backend; single-node and 4-node cluster)
- [x] Multi-vendor + Multi-hop Coordination (ros2 / mavlink / vendor_sdk with route/handoff evidence)
- [x] Acceptance Suite with criteria checks and KPI reporting

## Track 3 Requirement Summary

- **Coordination correctness**: deterministic bidding/commit flow with single-winner and no-double-assignment guarantees.
- **Resilience & recovery**: validated under delay/drop faults with partition recovery and hive-memory resynchronization.
- **Auditability & verification**: reproducible event/commit/proof artifacts with independent offline proof verification.
- **Security hardening**: signed message path, replay rejection, and commit equivocation guard.
- **Developer clarity & observability**: one-command acceptance flow with criteria checks and KPI metrics in machine-readable reports.

## Reviewer Quick Path

If you only have a few minutes, run these in order:

1. `python -m security_monitor.track3.main --mode acceptance --foxmq-backend simulated`
2. Open the generated `acceptance_report.json`
3. Confirm criteria and scenario checks are all `true`
4. For MQTT transport verification, run `Run All Track3 Cases (Including New Cases) With MQTT Environment` in the Run Guide.

For pre-validated hardened evidence, start here:

- MQTT: `artifacts/competition_req_check/acceptance_mqtt_10_hardened/acceptance_report.json`
- Official bridge: `artifacts/competition_req_check/acceptance_official_10_hardened/acceptance_report.json`

## Directory Structure

- `security_monitor/track3/`: Track 3 pure implementation + submission entrypoint (`protocol.py`, `main.py`)
- `security_monitor/swarm/`: Track 3 shared swarm logic and compatibility entry (`demo_track3.py`)
- `security_monitor/integration/`: transport and settlement integration (`foxmq_adapter.py`)
- `security_monitor/roles/`: scout / guardian / verifier behaviors
- `security_monitor/tests/`: e2e and acceptance-related tests

## Run Guide

Recommended review path: run `Acceptance (Simulated Transport)` first, then `Run All Track3 Cases With MQTT Environment`, and finally inspect `Artifact Outputs`.

### 1) Quick Demo

```bash
python -m security_monitor.track3.main
```

### 2) Acceptance (Simulated Transport)

```bash
python -m security_monitor.track3.main --mode acceptance --foxmq-backend simulated
```

### 3) Acceptance (Official FoxMQ MQTT Endpoint)

Script-first workflow (Windows):

1. Full one-click path (download + start FoxMQ + run acceptance):
   `powershell -ExecutionPolicy Bypass -File .\start_track3_with_mqtt.ps1`
2. Split path (keep FoxMQ running, then run tests in another terminal):
   `powershell -ExecutionPolicy Bypass -File .\start_foxmq.ps1`
3. With FoxMQ running, execute full MQTT unittest suite (see section `5.1` for exact commands).

Manual startup fallback:

Start FoxMQ with a reachable MQTT listener (for Windows loopback, bind explicitly to `127.0.0.1`):

```bash
artifacts\foxmq_runtime\foxmq.exe run --secret-key-file=artifacts\foxmq_runtime\foxmq.d\key_0.pem --allow-anonymous-login --mqtt-addr=127.0.0.1:1883 --cluster-addr=127.0.0.1:19793
```

Then run acceptance against that endpoint:

```bash
python -m security_monitor.track3.main --mode acceptance --foxmq-backend mqtt --foxmq-mqtt-addr 127.0.0.1:1883
```

### 4) Acceptance Against 4-Node Cluster (3N+1, N=1)

Use four FoxMQ nodes with distinct ports:

- Node0: MQTT `127.0.0.1:1883`, Cluster `127.0.0.1:19793`
- Node1: MQTT `127.0.0.1:1884`, Cluster `127.0.0.1:19794`
- Node2: MQTT `127.0.0.1:1885`, Cluster `127.0.0.1:19795`
- Node3: MQTT `127.0.0.1:1886`, Cluster `127.0.0.1:19796`

Run acceptance against any active node endpoint:

```bash
python -m security_monitor.track3.main --mode acceptance --foxmq-backend mqtt --foxmq-mqtt-addr 127.0.0.1:1886
```

### 5) MQTT E2E Test

```bash
set MQTT_E2E=1
set FOXMQ_MQTT_ADDR=127.0.0.1:1884
python -m unittest security_monitor.tests.test_swarm_track3.Track3SwarmTests.test_mqtt_transport_demo_e2e
```

PowerShell equivalent:

```bash
$env:MQTT_E2E="1"; $env:FOXMQ_MQTT_ADDR="127.0.0.1:1884"; python -m unittest security_monitor.tests.test_swarm_track3.Track3SwarmTests.test_mqtt_transport_demo_e2e
```

### 5.1) Run All Track3 Cases (Including New Cases) With MQTT Environment

Start broker in a dedicated terminal (recommended):

```bash
powershell -ExecutionPolicy Bypass -File .\start_foxmq.ps1
```

Manual equivalent:

```bash
artifacts\foxmq_runtime\foxmq.exe run --secret-key-file=artifacts\foxmq_runtime\foxmq.d\key_0.pem --allow-anonymous-login --mqtt-addr=127.0.0.1:1883 --cluster-addr=127.0.0.1:19793
```

Run full test suite with MQTT E2E enabled:

```bash
set MQTT_E2E=1
set FOXMQ_MQTT_ADDR=127.0.0.1:1883
set OFFICIAL_E2E=0
set OFFICIAL_MULTI_E2E=0
python -m unittest security_monitor.tests.test_swarm_track3 -v
```

PowerShell equivalent:

```bash
$env:MQTT_E2E="1"; $env:FOXMQ_MQTT_ADDR="127.0.0.1:1883"; $env:OFFICIAL_E2E="0"; $env:OFFICIAL_MULTI_E2E="0"; python -m unittest security_monitor.tests.test_swarm_track3 -v
```

Run acceptance scenarios under MQTT transport:

```bash
python -m security_monitor.track3.main --mode acceptance --foxmq-backend mqtt --foxmq-mqtt-addr 127.0.0.1:1883 --output-dir artifacts/acceptance_mqtt_latest
```

### 6) Reinforced Acceptance (10+ Agents + Multi-hop + Multi-vendor)

```bash
python -m security_monitor.track3.main --mode acceptance --workers 10 --foxmq-backend simulated --output-dir artifacts/competition_req_check/acceptance_simulated_10_reinforced
```

Acceptance checks covered in `acceptance_report.json`:

- `multi_vendor_readiness`
- `route_negotiation_handoff`
- `task_bidding`
- `hive_memory_state_sync`
- `verification_multisig_proof`
- `byo_agents_orchestrator_replaced`
- `security_attack_resistance`
- `observability_kpi_ready`
- `hive_memory_recovery`
- `commit_equivocation_guard`

## Artifact Outputs

Acceptance mode writes:

- `artifacts/<run_name>/acceptance_report.json`
- `artifacts/<run_name>/none|delay|drop/structured_event_log.json`
- `artifacts/<run_name>/none|delay|drop/coordination_proof.json`
- `artifacts/<run_name>/none|delay|drop/commit_log.json`

Pass condition: all fields in `criteria` are `true` in `acceptance_report.json`.

Latest validated evidence package:

- MQTT hardened acceptance: `artifacts/competition_req_check/acceptance_mqtt_10_hardened/acceptance_report.json`
- Official (Rust bridge) hardened acceptance: `artifacts/competition_req_check/acceptance_official_10_hardened/acceptance_report.json`
- Simulated hardened baseline: `artifacts/competition_req_check/acceptance_simulated_10_hardened/acceptance_report.json`

GitHub-friendly progress snapshot:

- `evidence/progress_evidence.json`
