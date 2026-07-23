/**
 * ブラウザ内で動くモック認可サーバー(IdP)。
 *
 * 実在の IdP には接続せず、OIDC の 4 エンドポイントを最小構成で再現する:
 *   - authorize : ユーザーを認証し、認可コードを発行する
 *   - token     : 認可コードを id_token / access_token に交換する
 *   - jwks      : id_token 検証用の公開鍵を配布する
 *   - userInfo  : access_token と引き換えにプロフィールを返す
 *
 * 署名・鍵はすべて Web Crypto 上(jose)で処理し、鍵はタブの外に出ない。
 */
import type { JWK } from "jose";
import { type SigningKey, createSigningKey, signIdToken } from "./oidc-crypto";
import type { CodeChallengeMethod } from "./pkce";
import { verifyPkce } from "./pkce";
import { randomUrlToken } from "./random";

export interface EndUser {
  sub: string;
  name: string;
  email: string;
}

/** IdP に登録済みのエンドユーザー（デモ用の 2 名）。 */
export const USERS = {
  alice: { sub: "user-alice", name: "Alice", email: "alice@example.com" },
  mallory: { sub: "user-mallory", name: "Mallory (攻撃者)", email: "mallory@evil.example" },
} satisfies Record<string, EndUser>;

export interface RegisteredClient {
  clientId: string;
  redirectUris: string[];
}

interface CodeRecord {
  clientId: string;
  redirectUri: string;
  user: EndUser;
  nonce?: string;
  codeChallenge?: string;
  codeChallengeMethod?: CodeChallengeMethod;
  used: boolean;
}

export interface AuthorizeRequest {
  responseType: string;
  clientId: string;
  redirectUri: string;
  scope: string;
  state?: string;
  nonce?: string;
  codeChallenge?: string;
  codeChallengeMethod?: CodeChallengeMethod;
}

export interface AuthorizeResult {
  code: string;
  /** IdP は state を解釈せず、そのまま RP に返す(エコーバック)。 */
  state?: string;
}

export interface TokenRequest {
  grantType: string;
  code: string;
  clientId: string;
  redirectUri: string;
  codeVerifier?: string;
}

export interface TokenResult {
  idToken: string;
  accessToken: string;
  tokenType: "Bearer";
  expiresIn: number;
}

/** OIDC のエラーレスポンス相当。 */
export class OidcError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = "OidcError";
    this.code = code;
  }
}

export class MockIdp {
  readonly issuer = "https://idp.example.com";
  private readonly key: SigningKey;
  private readonly client: RegisteredClient;
  private readonly codes = new Map<string, CodeRecord>();
  private readonly accessTokens = new Map<string, EndUser>();

  private constructor(key: SigningKey, client: RegisteredClient) {
    this.key = key;
    this.client = client;
  }

  /** 鍵ペアを生成して IdP を起動する。 */
  static async create(client: RegisteredClient): Promise<MockIdp> {
    return new MockIdp(await createSigningKey(), client);
  }

  /** JWKS エンドポイント: id_token 検証用の公開鍵。 */
  jwks(): JWK[] {
    return [this.key.publicJwk];
  }

  private assertClient(clientId: string, redirectUri: string): void {
    if (clientId !== this.client.clientId) {
      throw new OidcError("invalid_client", `未登録の client_id: ${clientId}`);
    }
    if (!this.client.redirectUris.includes(redirectUri)) {
      throw new OidcError("invalid_request", `未登録の redirect_uri: ${redirectUri}`);
    }
  }

  /**
   * authorize エンドポイント。
   * ここでユーザーは IdP にログイン済みとし、`user` として認可コードを発行する。
   * state / nonce / code_challenge はコードに紐付けて保存する。
   */
  authorize(req: AuthorizeRequest, user: EndUser): AuthorizeResult {
    if (req.responseType !== "code") {
      throw new OidcError("unsupported_response_type", req.responseType);
    }
    this.assertClient(req.clientId, req.redirectUri);

    const code = randomUrlToken(24);
    this.codes.set(code, {
      clientId: req.clientId,
      redirectUri: req.redirectUri,
      user,
      nonce: req.nonce,
      codeChallenge: req.codeChallenge,
      codeChallengeMethod: req.codeChallengeMethod,
      used: false,
    });
    return { code, state: req.state };
  }

  /**
   * token エンドポイント。認可コードを id_token / access_token に交換する。
   * PKCE が使われていれば code_verifier を検証する(横取り対策の要)。
   */
  async token(req: TokenRequest): Promise<TokenResult> {
    const record = this.codes.get(req.code);
    if (!record) throw new OidcError("invalid_grant", "認可コードが存在しません");
    if (record.used) throw new OidcError("invalid_grant", "認可コードは使用済みです(再利用不可)");
    if (req.clientId !== record.clientId) {
      throw new OidcError("invalid_client", "client_id がコードと一致しません");
    }
    if (req.redirectUri !== record.redirectUri) {
      throw new OidcError("invalid_grant", "redirect_uri がコードと一致しません");
    }

    // PKCE: authorize 時に challenge が登録されていれば verifier を必須にする。
    if (record.codeChallenge) {
      if (!req.codeVerifier) {
        throw new OidcError("invalid_grant", "code_verifier が必要です (PKCE)");
      }
      const ok = await verifyPkce(
        req.codeVerifier,
        record.codeChallenge,
        record.codeChallengeMethod ?? "S256",
      );
      if (!ok) throw new OidcError("invalid_grant", "PKCE 検証に失敗しました");
    }

    record.used = true;
    const accessToken = randomUrlToken(24);
    this.accessTokens.set(accessToken, record.user);

    const idToken = await signIdToken(this.key, {
      iss: this.issuer,
      sub: record.user.sub,
      aud: record.clientId,
      nonce: record.nonce,
      name: record.user.name,
      email: record.user.email,
    });
    return { idToken, accessToken, tokenType: "Bearer", expiresIn: 300 };
  }

  /** userInfo エンドポイント: access_token に対応するプロフィールを返す。 */
  userInfo(accessToken: string): EndUser {
    const user = this.accessTokens.get(accessToken);
    if (!user) throw new OidcError("invalid_token", "未知の access_token です");
    return user;
  }
}
