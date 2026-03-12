# agent-lite (Rust)

Lightweight benchmark/runtime prototype for small VPS targets.

## Run

```bash
cd /home/kurumonn/exkururuEDR/agent-lite
export EDR_AGENT_SHARED_SECRET=replace-with-test-secret
cargo run --release -- --events 1000 --loops 20
```

## Run with real input (CSV)

```bash
cd /home/kurumonn/exkururuEDR/agent-lite
cargo run --release -- \
  --events 0 \
  --input-csv /home/kurumonn/exkururuEDR/examples/edr_events_sample.csv \
  --loops 10000 \
  --out-jsonl /home/kurumonn/exkururuEDR/docs/agent_lite_normalized.jsonl \
  > /tmp/agent_lite_benchmark.json
```

## Notes

- This binary is optimized for memory/performance measurement.
- Signature implementation is benchmark-friendly (offline/no external crate).
- Production authentication contract remains the Python-side HMAC-SHA256 flow.
