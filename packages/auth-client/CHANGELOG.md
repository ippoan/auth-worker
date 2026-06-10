# Changelog — @ippoan/auth-client

## 0.1.37

- `VersionBadge`: 新規 prop `versionUrl` を追加。auth-worker の `/api/version` から
  適用済み plan (ippoan-dev-plans) の stage を取得し tooltip に追加表示する
  (5 件まで + 「他N件」)。plan がある時はバッジ click で plan 一覧
  (デフォルト: ippoan-dev-plans の issue リスト、`plansLink` prop で変更可) に遷移。
  取得失敗時は従来どおり version 表示のみで継続 (graceful degradation)。
  Refs ippoan/auth-worker#253
- `StagingFooter`: 同じく `versionUrl` / `plansLink` prop を追加。staging バーに
  plan サマリ (`Plans: <先頭 plan> +N`、title tooltip に全件) を表示。

## 0.1.36

- `StagingFooter`: staging export/import の opt-in 認証用に `stagingApiKey` prop を追加
  (`X-Staging-Key` ヘッダ)。Refs ippoan/rust-alc-api#391
