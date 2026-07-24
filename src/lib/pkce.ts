/**
 * PKCE (Proof Key for Code Exchange, RFC 7636)。
 *
 * 認可コードを盗まれても、それ単体ではトークンに交換できないようにする仕組み。
 *   1. RP は毎回ランダムな code_verifier を作る
 *   2. その SHA-256 ハッシュ(= code_challenge) を認可リクエストに載せる
 *   3. token 交換時に元の code_verifier を提示し、IdP がハッシュ一致を確認する
 *
 * 攻撃者はコードを横取りできても code_verifier を知らないため、交換に失敗する。
 */
import { base64urlEncode } from "./base64url";
import { randomUrlToken } from "./random";

export type CodeChallengeMethod = "S256" | "plain";

export interface PkcePair {
  /** 秘密の検証子。RP がセッション内に保持し、token 交換でだけ提示する。 */
  verifier: string;
  /** 認可リクエストに載せる公開値(S256 ならハッシュ)。 */
  challenge: string;
  method: CodeChallengeMethod;
}

/** code_verifier を SHA-256 でハッシュし、Base64url にした code_challenge。 */
export async function computeS256Challenge(verifier: string): Promise<string> {
  const data = new TextEncoder().encode(verifier);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return base64urlEncode(new Uint8Array(digest));
}

/** code_verifier と code_challenge のペアを生成する（既定は推奨方式 S256）。 */
export async function createPkcePair(method: CodeChallengeMethod = "S256"): Promise<PkcePair> {
  const verifier = randomUrlToken(32);
  const challenge = method === "S256" ? await computeS256Challenge(verifier) : verifier;
  return { verifier, challenge, method };
}

/** token 交換時: 提示された verifier が challenge と一致するか検証する。 */
export async function verifyPkce(
  verifier: string,
  challenge: string,
  method: CodeChallengeMethod,
): Promise<boolean> {
  const computed = method === "S256" ? await computeS256Challenge(verifier) : verifier;
  return computed === challenge;
}
