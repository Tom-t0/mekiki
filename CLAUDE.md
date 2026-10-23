# Mekiki（目利き）

日本語の詐欺・フィッシングメールを判定し、**根拠を示す**ツール。

このファイルは仕様の一次情報。実装の判断に迷ったらここを参照する。

---

## 1. 進め方のルール（厳守）

- 会話は**日本語**。コード内の識別子とコメントは英語。
- 実装の前に必ず計画を提示し、**承認を得てから**書き始める。
- 設計上の選択肢があるときは、メリット・デメリットを比較して提案し、**決定は作者に委ねる**。
- 変更は小さな単位で行い、各ステップで「何を・なぜそうしたか」を短く説明する。
- ロジックには必ず単体テストを書く。
- このリポジトリは就活で面接官に見せるもの。**作者自身が全てのコードを説明できる状態**を保つことが最優先。
  - ブラックボックスなライブラリに判定ロジックを委ねない（例: ドメイン類似判定は自作する）。
  - 賢いが読みにくいコードより、素直で説明しやすいコードを選ぶ。

## 2. 安全とデータの扱い（厳守）

- `data/` は `.gitignore` 済み。**中身を絶対にコミットしない。**
- 実在の人から集めたメールをリポジトリに入れない。
- テスト用のメールは**すべて自作の合成データ**。ドメインは `example.com` / `example.jp` 系など架空のものだけを使う。
- **メール中のURLにネットワークアクセスしない。**
- `data/`（収集した実データ、コミットしない）と `src/mekiki/resources/`（同梱する辞書類、コミットする）は別物。混ぜない。

## 3. 対象範囲

- 対象は**「企業・機関を名乗るメール」のみ**。
- 個人間のやり取りは対象外 → 判定を出さず「対象外」と表示する。

## 4. 段階計画

| 段階 | 内容 |
|---|---|
| 第1段階（現在） | メールヘッダーを使わない。Chrome拡張でGmailの画面上のメールを解析。ルールによる技術チェック ＋ LLMによる手口判定。 |
| 第2段階 | ヘッダーの認証結果、ドメイン登録日、**同意を得たうえでの**リンク先解析を追加。 |
| 第3段階 | 集めたデータで軽量モデルを学習し、LLMの判定を置き換える。 |

## 5. ラベル体系（確定済み）

### 最上位の判定（1つ選ぶ）

| verdict | 付随情報 |
|---|---|
| `scam`（詐欺） | `confidence` = `high` / `low` |
| `legit`（正常） | `confidence` = `high` / `low` |
| `ad`（広告） | `ad_risk` = `high` / `low` |
| `undeterminable`（判定不能） | `exclusion_reason` = `missing_content` / `unsupported_format` |

- `ad_risk = high` の条件（いずれか1つでも該当）:
  高額な支払い・契約 / 元本保証や高利回りをにおわせる投資 / 解約条件が分かりにくい定期購入 /
  収入や健康効果を断定する誇大表現 / 不要な個人情報の要求
- `exclusion_reason`: `missing_content` = データ自体が欠けている、`unsupported_format` = 扱えない形式

### 軸1：名乗っている送信者（内部データのみ。ユーザーには表示しない）

- `claimed_entity`: 組織名を手で記録する。
- `sender_category`: 組織名→カテゴリの対応表（`resources/sender_categories.json`）から**自動付与**。
  - 銀行 / カード会社 / 証券・投資 / 通販・EC / 決済・ポイント / 配送 / 通信・IT / 公共料金・インフラ / 公的機関 / なし・その他

### 軸2：説得の手口（複数可）

| ラベル | 意味 |
|---|---|
| `authority` | 権威：従わなければならない圧力 |
| `urgency` | 緊急性：期限を切って急がせる |
| `loss_threat` | 損失の脅し |
| `gain_offer` | 利得の提示 |
| `curiosity` | 好奇心 |
| `routine_procedure` | 手続き型：事務連絡の体裁で油断させる |

### 軸3：要求している行動（複数可。危険度はラベルごとに固定。メールの危険度はその最大値）

| 危険度 | ラベル |
|---|---|
| 中 (`medium`) | `open_link`, `scan_qr`, `reply` |
| 高 (`high`) | `open_attachment`, `enter_credentials`, `call_phone` |
| 最高 (`critical`) | `enter_payment_info`, `send_money`, `install_app` |

### 軸4：技術的な偽装（ルールで自動判定。複数可）

第1段階:
`display_name_mismatch`, `link_mismatch`, `lookalike_domain`, `url_shortener`,
`open_redirect`, `ip_address_url`, `image_heavy_body`, `embedded_qr`, `known_malicious`

第2段階:
`newly_registered_domain`

### ラベル付けのルール

- **本文に根拠がある場合だけ**付ける。
- **正常メールにも軸1〜3を付ける**（正常メールにも「手口」や「要求行動」は存在する）。
- 内部ラベル名は**中立**にし、ユーザーへの表示文は判定に応じて書き分ける。
  （例: `open_link` は詐欺なら「リンクを開かせようとしています」、正常なら「リンクが含まれます」）

## 6. ホワイトリスト

- 組織名ごとの正規ドメイン一覧を持つ（`resources/whitelist.json`）。
- 用途は**軸4のルール（`display_name_mismatch`, `link_mismatch` など）が本物の企業メールに誤反応しないようにすることだけ**。
- **「安全」の判定には絶対に使わない。** 正規ドメインからのフィッシングも存在するため。

## 7. 技術スタックと決定事項

| 項目 | 決定 | 理由 |
|---|---|---|
| 言語 | Python 3.13（`requires-python >= 3.12`） | |
| 型・バリデーション | Pydantic v2 | 拡張から来るJSONと将来のLLM出力JSONの検証が中核になるため |
| テスト | pytest のみ | lint / 型チェックは必要になったら追加 |
| 構成 | `src/` レイアウト | テストがインストール相当の状態でimportするため |
| 拡張との接続 | **未決定** | 候補: ローカルHTTP API（判定は全部Python）／TS側でルールを再実装。決まるまで `extension/` は作らない |

## 8. ディレクトリ構成

```
mekiki/
├── CLAUDE.md               # このファイル（仕様の一次情報）
├── pyproject.toml          # 依存 + pytest 設定
├── data/                   # 収集した実データ。中身はコミットしない
├── src/mekiki/
│   ├── labels.py           # ラベル体系（軸1〜4、verdict）
│   ├── email_input.py      # 正規化された入力型
│   ├── urls.py             # URL/ドメインの抽出・正規化（全ルールの土台）
│   ├── whitelist.py        # ホワイトリストの読み込みと参照
│   ├── resources/          # 同梱辞書（コミットする）
│   │   ├── whitelist.json
│   │   ├── sender_categories.json
│   │   └── shorteners.txt
│   └── rules/              # 軸4のルール。1ファイル1ルール
│       ├── base.py         # Rule プロトコル + RuleFinding
│       └── registry.py     # ルールの登録と一括実行
├── tests/
│   └── fixtures/emails/    # 自作の合成メール
└── tools/                  # 将来のラベル付けCLI
```

## 9. 開発コマンド

Windows + Git Bash を想定。`python` はストアのスタブなので使わない（venv か `py -3` を使う）。

```bash
# 初回のみ
py -3 -m venv .venv
./.venv/Scripts/python.exe -m pip install -e ".[dev]"

# テスト
./.venv/Scripts/python.exe -m pytest -q
```
