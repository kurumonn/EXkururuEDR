# exkururuEDR パッケージングガイド

## Python パッケージ

```bash
cd /path/to/exkururuEDR
python3 -m pip install --upgrade build
python3 -m build
```

生成物:

- `dist/*.whl`
- `dist/*.tar.gz`

## Rust agent-lite バイナリ

```bash
cd /path/to/exkururuEDR/agent-lite
cargo build --release
```

## リリース確認項目

1. 公開 README を確認する
2. 共通認証契約のサンプルが動作する
3. ライセンスファイルが存在する
