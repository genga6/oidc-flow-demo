/**
 * id_token の署名・検証（JOSE / jose ライブラリ、RS256）。
 *
 * OIDC の id_token は RS256 で署名された JWT。IdP が秘密鍵で署名し、
 * RP は IdP の JWKS(公開鍵)で検証する。姉妹デモ jwt-tampering-demo と同じく、
 * 署名検証こそがクレーム(sub など)を信頼してよい唯一の根拠になる。
 *
 * すべてブラウザ/Node の Web Crypto 上で動き、秘密鍵はこのタブから外に出ない。
 */
import {
  type JWK,
  type JWTPayload,
  type KeyLike,
  SignJWT,
  calculateJwkThumbprint,
  createLocalJWKSet,
  decodeJwt,
  exportJWK,
  generateKeyPair,
  errors as joseErrors,
  jwtVerify,
} from "jose";

export interface SigningKey {
  /** 署名に使う秘密鍵。 */
  privateKey: KeyLike;
  /** JWKS で配布する公開鍵(kid / alg / use 付き)。 */
  publicJwk: JWK;
  /** 公開鍵のサムプリントから決まる鍵 ID。 */
  kid: string;
}

/** RS256 の鍵ペアを生成し、公開鍵を JWKS 用の JWK として返す。 */
export async function createSigningKey(): Promise<SigningKey> {
  const { privateKey, publicKey } = await generateKeyPair("RS256", { extractable: true });
  const jwk = await exportJWK(publicKey);
  const kid = await calculateJwkThumbprint(jwk);
  const publicJwk: JWK = { ...jwk, kid, alg: "RS256", use: "sig" };
  return { privateKey, publicJwk, kid };
}

export interface IdTokenClaims {
  iss: string;
  sub: string;
  aud: string;
  nonce?: string;
  name?: string;
  email?: string;
}

/** id_token(RS256 署名付き JWT)を発行する。 */
export async function signIdToken(
  key: SigningKey,
  claims: IdTokenClaims,
  ttlSeconds = 300,
): Promise<string> {
  const { iss, sub, aud, nonce, name, email } = claims;
  const payload: JWTPayload = {};
  if (nonce !== undefined) payload.nonce = nonce;
  if (name !== undefined) payload.name = name;
  if (email !== undefined) payload.email = email;

  return new SignJWT(payload)
    .setProtectedHeader({ alg: "RS256", kid: key.kid, typ: "JWT" })
    .setIssuedAt()
    .setIssuer(iss)
    .setSubject(sub)
    .setAudience(aud)
    .setExpirationTime(`${ttlSeconds}s`)
    .sign(key.privateKey);
}

export interface VerifyResult {
  valid: boolean;
  payload?: JWTPayload;
  error?: string;
}

/**
 * id_token を JWKS で検証する（署名 + iss/aud/exp）。
 * 偽造・改ざん・期限切れ・issuer/audience 不一致はすべて失敗になる。
 */
export async function verifyIdToken(
  token: string,
  jwks: JWK[],
  opts: { issuer: string; audience: string },
): Promise<VerifyResult> {
  try {
    const keyStore = createLocalJWKSet({ keys: jwks });
    const { payload } = await jwtVerify(token, keyStore, {
      issuer: opts.issuer,
      audience: opts.audience,
    });
    return { valid: true, payload };
  } catch (err) {
    return { valid: false, error: describeJoseError(err) };
  }
}

/**
 * 署名を検証せずに id_token のクレームだけ取り出す（危険）。
 * 「id_token 検証」を OFF にした RP の挙動を再現するためのもの。
 */
export function decodeIdTokenUnsafe(token: string): JWTPayload {
  return decodeJwt(token);
}

/** jose の例外を画面表示向けのメッセージに変換する。 */
function describeJoseError(err: unknown): string {
  if (err instanceof joseErrors.JWKSNoMatchingKey) {
    return "JWKS に一致する鍵がありません — IdP が発行していない鍵で署名された偽造トークンです。";
  }
  if (err instanceof joseErrors.JWSSignatureVerificationFailed) {
    return "署名検証に失敗しました — 改ざんされたか、鍵が一致しません。";
  }
  if (err instanceof joseErrors.JWTExpired) {
    return "id_token の有効期限が切れています。";
  }
  if (err instanceof joseErrors.JWTClaimValidationFailed) {
    return `クレーム検証に失敗しました (${err.claim}) — iss/aud が想定と一致しません。`;
  }
  if (err instanceof joseErrors.JOSEError) {
    return `${err.code}: ${err.message}`;
  }
  return err instanceof Error ? err.message : String(err);
}
