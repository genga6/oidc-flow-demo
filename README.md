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
