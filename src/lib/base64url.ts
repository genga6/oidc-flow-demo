/**
 * Base64url エンコード/デコード (ブラウザ向け・Buffer 非依存)。
 *
 * JWT(id_token) の各セグメントや PKCE の値はいずれも Base64url で表現される。
 * 通常の Base64 との違い:
 *   - `+` → `-`, `/` → `_`
 *   - 末尾の `=` パディングを削除
 *
 * 重要: Base64url は「エンコード」であって「暗号化」ではない。
 * 姉妹デモ jwt-tampering-demo で扱ったとおり、鍵なしで誰でも中身を読める。
 * だからこそ id_token は「署名検証」があって初めて信頼できる。
 */

/** 文字列(UTF-8)またはバイト列を Base64url 文字列にエンコードする。 */
export function base64urlEncode(input: string | Uint8Array): string {
  const bytes = typeof input === "string" ? new TextEncoder().encode(input) : input;
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Base64url 文字列をバイト列にデコードする。 */
export function base64urlDecodeToBytes(input: string): Uint8Array {
  const b64 = input.replace(/-/g, "+").replace(/_/g, "/");
  const pad = b64.length % 4 === 0 ? "" : "=".repeat(4 - (b64.length % 4));
  const binary = atob(b64 + pad);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

/** Base64url 文字列を UTF-8 文字列にデコードする。 */
export function base64urlDecodeToString(input: string): string {
  return new TextDecoder().decode(base64urlDecodeToBytes(input));
}

/** JSON 値を Base64url エンコードする。 */
export function base64urlEncodeJson(value: unknown): string {
  return base64urlEncode(JSON.stringify(value));
}

/** Base64url セグメントを JSON としてデコードする。 */
export function base64urlDecodeJson<T = unknown>(input: string): T {
  return JSON.parse(base64urlDecodeToString(input)) as T;
}
