# oidc-flow-demo

**🔗 ライブデモ: https://genga6.github.io/oidc-flow-demo/**

[![Deploy to GitHub Pages](https://github.com/genga6/oidc-flow-demo/actions/workflows/deploy.yml/badge.svg)](https://github.com/genga6/oidc-flow-demo/actions/workflows/deploy.yml)

OpenID Connect (OIDC) の **認可コードフロー + PKCE** を、ブラウザ内で動くモック IdP
（認可サーバー）で再現する教材デモ。**state / nonce / PKCE / id_token 検証** の各防御を
トグルで OFF にすると、対応する攻撃が成立してしまう様子を体験できる。

署名・鍵生成・id_token 検証はすべてブラウザの Web Crypto 上（[jose](https://github.com/panva/jose)）で
動作し、実在の IdP には接続しない。鍵はタブの外に出ない。

姉妹デモ [jwt-tampering-demo](https://github.com/genga6/jwt-tampering-demo) が
**id_token 単体の署名検証**を扱うのに対し、こちらはその id_token をやり取りする
**OIDC のフロー全体とその防御機構**を扱う続編・発展版。

## フローの考え方（OAuth との関係）

### OIDC は OAuth の拡張

フローの骨格は OAuth 2.0 の認可コードフローと同じで、OIDC はそこに
**署名付き id_token と UserInfo**（＝「誰がログインしたか」の認証）を上乗せしたもの。
登場人物も名前が変わるだけで実体は同じ（このデモでは 1 つの `MockIdp` が兼ねる）。

| OAuth の呼び名 | OIDC の呼び名 | 実体 | 主眼 |
| --- | --- | --- | --- |
| クライアント | RP (Relying Party) | 使いたいサービス | — |
| 認可サーバー | **IdP** (Identity Provider) | ログインを担当する 1 台（例: Cognito / Supabase） | 認可 → **認証**も兼ねる |
| リソースオーナー | エンドユーザー | 人間 | — |

同じ token エンドポイントから **access_token（認可: 何ができるか）** と
**id_token（認証: 誰なのか）** の両方が返る。宛先は逆で、access_token は API（IdP 等）に提示する券、
id_token は RP 自身が読んで検証する身分証（`aud` = client_id）。ログインだけなら
access_token は使わず、`scope` を最小（`openid profile email`）にして id_token を検証すればよい。

### 一発でトークンをもらわず「引換券 → 検証 → 交換」の 2 段構え

このフローの肝は、認可リクエストの応答でトークンを**直接もらわない**こと。
まず**認可コード（引換券）**だけを受け取り、検証を挟んでから**別チャネルでトークンに交換**する。
下図の ①〜⑦ は、デモの正常フロー可視化のステップとそのまま対応する
（レーン＝デモの `ブラウザ / RP / IdP`）。

```
  ユーザー / ブラウザ        クライアント (RP)           IdP (認可サーバー)
       │                        │                          │
       │  ①「ログインしたい」    │                          │
       │───────────────────────►│ state / nonce / PKCE生成 │
       │                        │                          │
       │       ② 認可リクエストで IdP へリダイレクト          │
       │═══════════════════════════════════════════════════►│ ③本人を認証し
       │        (フロントチャネル = URL 経由・漏れやすい)      │   認可コードを発行
       │                                                    │
       │       ③ 認可コード(引換券) が URL で戻る             │
       │◄═══════════════════════════════════════════════════│
       │───────────────────────►│ ④ state を照合            │
       │  (ブラウザが RP に渡す)  │                          │
       │                        │── ⑤ code + verifier ───►│ PKCE を検証し
       │                        │                          │ トークンを発行
       │                        │◄─ id_token + access ─────│
       │                        │ ⑥ id_token 署名検証+nonce │
       │                        │── ⑦ access_token ──────►│ UserInfo
       │                        │◄─ プロフィール ───────────│
       │  ⑦ ログイン完了         │                          │
       │◄───────────────────────│                          │
```

- **`═══`（二重線）= フロントチャネル**: ブラウザが URL 経由で IdP と直接やり取りする区間。
  RP の列を素通りしているのがポイント（RP はブラウザに「行ってきて」と促すだけ）。
  ここに載るのは**引換券（認可コード）だけ**。
- **`───`（一重線）= バックチャネル**: RP と IdP のサーバー間直接通信。⑤の**本物のトークン交換**はここで、
  他人に見えない。

トークンそのものをブラウザの URL に出さないので、途中で URL が漏れても盗まれるのは
「引換券」だけ。そして引換券も、PKCE により**開始した本人でないと交換できない**。

### state / nonce / PKCE は「跳ねる各区間を開始セッションに紐付ける」道具

フローはブラウザ（信用できない場所）を経由して跳ねるため、「今戻ってきた応答は
確かにさっき自分が始めたログインの続きか？」を区間ごとに証明する。開始時に秘密を作り、
戻ってきたときに突き合わせる、という発想は 3 つとも共通で、**守る区間**だけが違う。

| 要素 | 出自 | 何を今回のセッションに紐付けるか | 守る攻撃 |
| --- | --- | --- | --- |
| **state** | OAuth | ③④ 戻ってきたコールバック（URL に載って戻る） | CSRF / 認可コード注入 |
| **PKCE** | OAuth (RFC 7636) | ⑤ コード→トークン交換（`verifier` のハッシュを照合） | 認可コード横取り |
| **nonce** | **OIDC** | ⑥ 受け取った id_token（署名付きトークンの中に入って戻る） | id_token リプレイ |

state と nonce は似ているが**帰り道が違う**：state は URL（フロントチャネル）で、
nonce は id_token の中身（＝OIDC 前提）で戻る。PKCE だけは値の突き合わせでなく
`SHA256(verifier) == challenge` のチャレンジ&レスポンスで、引換券を盗まれても換金させない。

## デモの内容

### ① 正常フローの段階可視化

認可リクエスト → ログイン → 認可コード発行 → トークン交換 → id_token 検証 → UserInfo までを、
**ブラウザ / RP（クライアント）/ IdP（認可サーバー）** 間のやり取りとしてステップ表示する。
防御を OFF にすると、対応する手順（state 照合・nonce 照合・PKCE・署名検証）が省かれていく。

### ② 防御を外すと成立する攻撃

各防御をトグルで無効化すると、対応する攻撃が「防御で阻止」から「攻撃成立」に変わる。

| 無効化する防御 | 成立する攻撃 | なぜ防げるのか |
| --- | --- | --- |
| **state** | CSRF / 認可コード注入 | RP がコールバックの `state` を自セッションの値と照合し、攻撃者が注入したコードを弾く。 |
| **nonce** | id_token リプレイ | RP が id_token の `nonce` を今回のログインに束縛し、過去トークンの使い回しを検出する。 |
| **PKCE** | 認可コード横取り | 認可コードを `code_verifier` を知るクライアントに束縛し、横取りしたコードの交換を防ぐ。 |
| **id_token 署名/クレーム検証** | 偽造 id_token の受理 | RP が JWKS で署名と `iss` / `aud` / `exp` を検証し、偽造・格下げトークンを拒否する。 |

いずれの攻撃も、対応する防御 **1 つだけ**で結果が決まるように構成している（他の防御には依存しない）。

## 使い方

```bash
pnpm install
pnpm dev       # http://localhost:5173
```

その他のスクリプト:

```bash
pnpm build     # tsc による型チェック + 本番ビルド
pnpm test      # vitest（フローと各攻撃のロジックを検証）
pnpm lint      # biome チェック
pnpm format    # biome フォーマット
```

## 構成

| パス | 役割 |
| --- | --- |
| `src/lib/base64url.ts` | Base64url エンコード/デコード（`Buffer` 非依存のブラウザ実装） |
| `src/lib/random.ts` | state / nonce / code_verifier 用の CSPRNG 乱数生成 |
| `src/lib/pkce.ts` | PKCE の code_verifier / code_challenge (S256) 生成と検証 |
| `src/lib/oidc-crypto.ts` | jose による RS256 署名・JWKS 検証・鍵生成 |
| `src/lib/mock-idp.ts` | モック認可サーバー（authorize / token / jwks / userInfo） |
| `src/lib/relying-party.ts` | RP のフロー実行とステップ記録（防御の ON/OFF を反映） |
| `src/lib/attacks.ts` | 4 つの攻撃シミュレーション（防御 ON で阻止 / OFF で成立） |
| `src/components/OidcDemo.tsx` | 防御トグル + 正常フロー可視化 + 攻撃マトリクスの本体 |
| `src/components/ui.tsx` | 共通 UI 部品（バッジ・トグル・データ表示など） |
| `test/` | PKCE・フロー・各攻撃の自動テスト |

## セキュリティ上の注意

このモック IdP は**教材専用**であり、本番の認可サーバーとして使ってはならない。
実装は攻撃の成立条件を分かりやすく見せることを優先しており、実運用に必要な検証
（トークンの失効、redirect_uri の厳密照合、レート制限など）は最小限にとどめている。

## 技術スタック

Vite + React 19 + TypeScript + Tailwind CSS v4 / jose (RS256・JWKS) / Biome / Vitest
