/**
 * デモ全体で共有する型。
 *
 * OIDC 認可コードフロー + PKCE の「防御」を 4 つのトグルで表現する。
 * それぞれを OFF にすると、対応する攻撃が成立してしまう:
 *   - state               … CSRF / 認可コード注入
 *   - nonce               … id_token リプレイ
 *   - pkce                … 認可コード横取り
 *   - idTokenValidation   … 偽造 id_token の受理
 */
export interface Defenses {
  /** RP が state を生成しコールバックで照合する（CSRF / コード注入対策）。 */
  state: boolean;
  /** RP が nonce を生成し id_token のクレームと照合する（リプレイ対策）。 */
  nonce: boolean;
  /** RP が code_verifier/challenge を用い、IdP が token で検証する（横取り対策）。 */
  pkce: boolean;
  /** RP が JWKS で id_token の署名とクレーム(iss/aud/exp)を検証する。 */
  idTokenValidation: boolean;
}

/** 防御キーの一覧（UI のトグルや反復に使う）。 */
export const DEFENSE_KEYS = ["state", "nonce", "pkce", "idTokenValidation"] as const;

export type DefenseKey = (typeof DEFENSE_KEYS)[number];
