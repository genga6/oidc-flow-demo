/**
 * 予測不能なランダム値の生成。
 *
 * state / nonce / 認可コード / PKCE の code_verifier など、OIDC では
 * 「攻撃者に推測されないこと」が安全性の前提になる値が多い。
 * ブラウザ/Node いずれでも Web Crypto の CSPRNG を使う。
 */
import { base64urlEncode } from "./base64url";

/** 指定バイト数の乱数を Base64url 文字列で返す（URL 安全・パディングなし）。 */
export function randomUrlToken(byteLength = 32): string {
  const bytes = new Uint8Array(byteLength);
  crypto.getRandomValues(bytes);
  return base64urlEncode(bytes);
}
