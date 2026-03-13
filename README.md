# exkururuEDR

[英語版 README](README.en.md)  
[4製品デモ概要](README.4stack.md)

EXkururuEDR は、EXkururu スタックのエンドポイント検知・対応コンポーネントです。  
この公開リポジトリでは、外部に見せる価値が高い範囲だけを残しています。具体的には、端末イベント正規化、エージェント構成、共通イベント契約、ローカル実行ツール類です。

## 公開範囲

- Linux エージェント骨格
- エンドポイントイベント正規化
- 共通イベント契約の利用面
- XDR 連携用エクスポート経路
- ローカル CLI とテスト

検知精度に直結する詳細なルール調整、実運用向け閾値、性能上の核心ノウハウは公開版から除外しています。

## クイックスタート

```bash
cd /path/to/exkururuEDR
PYTHONPATH=src python -m pytest -q
```

サンプル正規化:

```bash
cd /path/to/exkururuEDR
python -m exkururuedr.cli ./sample_raw_event.json --pretty
```

## 公開している主な資産

- 共通認証契約: `docs/auth_shared_secret_contract.md`
- 軽量 Rust エージェント構成: `agent-lite/`
- ローカル実行向けサンプル設定・サンプルイベント

## 主な機能

- ローカル収集とルール評価
- 共通契約へのイベント正規化
- XDR へのイベント送信
- ヘルスチェックとスプール前提のエージェント動作
