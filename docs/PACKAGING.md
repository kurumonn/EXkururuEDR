# exkururuEDR Packaging Guide

## Python package

```bash
cd /path/to/exkururuEDR
python3 -m pip install --upgrade build
python3 -m build
```

Artifacts:

- `dist/*.whl`
- `dist/*.tar.gz`

## Rust agent-lite binary

```bash
cd /path/to/exkururuEDR/agent-lite
cargo build --release
```

## Release checklist

1. Public README reviewed.
2. Shared-auth contract sample works.
3. License file present.
