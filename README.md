# Mekiki（目利き）

日本語の詐欺・フィッシングメールを判定し、**根拠を示す**ツール。

「怪しい」と言うだけのツールにはしない。どの文・どのURL・どの差分がそう判断させたのかを必ず提示する、というのがこのプロジェクトの出発点です。

> **現在の状態**: 第1段階のコアロジック（型定義・URL解析・技術的偽装ルール7本）が実装済み。
> Chrome拡張とLLM判定は未着手です。詳しい仕様は [CLAUDE.md](CLAUDE.md) にあります。

---

## 何をするものか

- 対象は**企業・機関を名乗るメールのみ**。個人間のやり取りは判定せず「対象外」とする。
- 判定は2系統の組み合わせ。
  - **ルール**: 機械的に判定できる技術的な偽装（軸4）。本リポジトリの実装範囲。
  - **LLM**: 文面から読み取る説得の手口（軸2）と要求された行動（軸3）。未実装。
- メール中のURLには**一切アクセスしない**。ヘッダーも第1段階では使わない。

## ラベル体系

最上位の判定を1つ選び、4つの軸でラベルを付けます（詳細は [CLAUDE.md](CLAUDE.md) 第5節、実装は [labels.py](src/mekiki/labels.py)）。

| 判定 | 付随情報 |
|---|---|
| `scam` / `legit` | `confidence` = high / low |
| `ad` | `ad_risk` = high / low |
| `undeterminable` | `exclusion_reason` = missing_content / unsupported_format |

| 軸 | 内容 |
|---|---|
| 1. 名乗っている送信者 | `claimed_entity` と `sender_category`（内部データ。ユーザーには表示しない） |
| 2. 説得の手口 | authority / urgency / loss_threat / gain_offer / curiosity / routine_procedure |
| 3. 要求している行動 | 危険度は固定（中 / 高 / 最高）。メールの危険度はその最大値 |
| 4. 技術的な偽装 | ルールで自動判定。下表参照 |

設計上の要点が2つあります。

- **ラベル名は中立**（`open_link`、`malicious_link` ではない）。正常メールにも軸1〜3を付けるため。表示文は判定に応じて書き分けます。
- **ラベルには必ず根拠（`Evidence`）が紐づく**。`AnalysisResult` のバリデータが、付いていないラベルに対する根拠を拒否します。

## 実装済みのルール（軸4・第1段階）

| ルール | 反応する条件 | 反応しない例（誤反応対策） |
|---|---|---|
| [display_name_mismatch](src/mekiki/rules/display_name_mismatch.py) | 表示名が名乗る組織・ドメインと、実際の送信元ドメインが食い違う | 同じ組織の第2ドメイン、サブドメイン、ホワイトリストにない組織（判定しない） |
| [link_mismatch](src/mekiki/rules/link_mismatch.py) | リンクの表示文字列が示すサイトと、実際のhrefのドメインが違う | 「ご確認はこちら」等（サイトを名乗っていない）、同一組織の配信ドメイン、`.pdf` 等のファイル名 |
| [lookalike_domain](src/mekiki/rules/lookalike_domain.py) | 正規ドメインに対し、混同文字・編集距離1・同名別TLD のいずれかで似ている | 正規ドメイン自身とそのサブドメイン、無関係なドメイン、IPアドレス、短い組織名 |
| [url_shortener](src/mekiki/rules/url_shortener.py) | リンクが短縮URLサービス経由 | 似た名前の無関係なドメイン |
| [open_redirect](src/mekiki/rules/open_redirect.py) | リダイレクト用パラメータが別ドメインのURLを運んでいる | 同一サイト内のクリック計測、検索クエリ（`?q=`）、相対パス |
| [ip_address_url](src/mekiki/rules/ip_address_url.py) | リンク先ホストが生のIPアドレス（整数表記・IPv6も） | 数字を含むだけのドメイン、`mailto:` など |
| [image_heavy_body](src/mekiki/rules/image_heavy_body.py) | 画像2枚以上かつ本文テキスト100文字以下 | 画像の多い本物のメルマガ（本文が十分ある） |

インターフェースのみ（未実装）:

| ルール | 必要なもの |
|---|---|
| [known_malicious](src/mekiki/rules/known_malicious.py) | ローカルに保持するブロックリスト。解析時に外部APIへ問い合わせない方針を守るため |
| [embedded_qr](src/mekiki/rules/embedded_qr.py) | 画像データ本体とQRデコーダ。入力型にデータを持たせる判断が必要 |

第2段階の `newly_registered_domain` はラベルだけ定義済みで、ルールはまだありません。

## ホワイトリスト

[whitelist.json](src/mekiki/resources/whitelist.json) に組織ごとの正規ドメインを持ちます。

- **用途**: 軸4のルールが本物の企業メールに誤反応しないようにすること。
- **用途ではないこと**: 「安全」の判定。正規ドメインからのフィッシングも存在するため、ホワイトリストの一致を `legit` の根拠にするコードは書きません。

サンプルデータの組織はすべて架空で、ドメインは RFC 2606 の予約名前空間 `.example` のみを使っています。これは「絶対に実在の企業を指さない」ための選択で、`example.com` のサブドメイン形式にしなかった理由は、全組織の登録可能ドメインが `example.com` に潰れてリンク判定が成立しなくなるためです（テストで検証しています）。

## 安全とデータの扱い

- `data/` は `.gitignore` 済み。収集したメールを**コミットしない**。
- リポジトリ内のメールデータは `tests/fixtures/emails/` の自作合成メール2通だけ。
- メール中のURLにネットワークアクセスしない。

## 構成

```
src/mekiki/
├── labels.py        ラベル体系（判定・軸1〜4・根拠）
├── email_input.py   解析対象の正規化された入力型
├── urls.py          URL/ドメインの解析（全ルールの土台）
├── similarity.py    編集距離と混同文字の正規化（自作）
├── whitelist.py     正規ドメイン表と組織名→カテゴリ表
├── resources_io.py  同梱データファイルの読み込み
└── rules/
    ├── base.py      ルールの形（関数・RuleFinding・RuleContext）
    ├── registry.py  ルール一覧と一括実行
    └── *.py         1ファイル1ルール
```

ルールは「メール + 参照データ → 所見のリスト」の純粋な関数です。ファイルを読まず、判定も下しません。所見を判定に組み上げるのは別の層の仕事です。

## セットアップ

Windows + Git Bash を想定（`python` はストアのスタブなので使いません）。

```bash
py -3 -m venv .venv
./.venv/Scripts/python.exe -m pip install -e ".[dev]"
./.venv/Scripts/python.exe -m pytest -q
```

## コードの読みどころ

- [tests/test_registry.py](tests/test_registry.py) の `test_a_legitimate_bank_notice_produces_no_signal` — 本物の銀行メール（表示文は主ドメイン・リンクは配信ドメイン・画像あり）に対して所見が1件も出ないことを確認する、このプロジェクトで最も重要なテスト。
- [similarity.py](src/mekiki/similarity.py) — 編集距離と混同文字テーブルを自分で書いています。「どこまで似ていたら偽装か」はこのツールが下す唯一の主観的な判断なので、ライブラリに隠したくなかった部分です。
- [labels.py](src/mekiki/labels.py) の `AnalysisResult` — 判定と付随情報の対応、根拠と割り当て済みラベルの整合性を、型の時点で強制しています。

## 既知の限界

- 公開接尾辞リスト（PSL）は手書きの小さな部分集合です。`co.jp` 等は対応済みですが、`city.sapporo.jp` のような地域ドメインは未対応。
- `lookalike_domain` は編集距離1までなので、文字の入れ替え（`bnak`）は検出できません（混同文字テーブルが一部を補っています）。
- `display_name_mismatch` の組織判定はホワイトリストにある組織にしか効きません。未知の組織については黙る設計です。
- 拡張機能とコアの接続方式（ローカルHTTP API か TS側での再実装か）は未決定です。
