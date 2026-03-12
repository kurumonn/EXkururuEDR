# exkururuEDR

[English README](README.en.md)
[4-stack demo note](README.4stack.md)

EXkururuEDR is the endpoint detection and response component of the EXkururu stack.
The public repository keeps the product surface that is valuable to show openly: endpoint event
normalization, agent layout, shared event contract, and local tooling.

## Public scope

- Linux agent skeleton
- Endpoint event normalization
- Shared event contract usage
- XDR export surface
- Local CLI and tests

Detailed rule tuning, production thresholds, and implementation notes that directly encode detection quality
or runtime advantages are intentionally excluded from the public distribution.

## Quick Start

```bash
cd /path/to/exkururuEDR
PYTHONPATH=src python -m pytest -q
```

Sample normalization:

```bash
cd /path/to/exkururuEDR
python -m exkururuedr.cli ./sample_raw_event.json --pretty
```

## Public assets

- Local run and packaging notes are kept minimal in this repository
- Shared-auth contract: `docs/auth_shared_secret_contract.md`
- Agent-lite layout: `agent-lite/`

## Main capabilities

- Local collection and rule evaluation
- Event normalization into the shared contract
- XDR export path
- Health and spool-oriented agent workflow
# EXkururuEDR
