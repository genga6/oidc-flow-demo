/**
 * RP(クライアント)側のフロー実行。
 *
 * ブラウザ / RP / IdP のやり取りとして、認可コードフロー + PKCE を 1 回分実行し、
 * 各ステップを記録して返す。防御(Defenses)を OFF にすると、そのステップの
 * チェックを省略する — 正常系はどの設定でも成功するが、防御は薄くなる。
 */
import { type EndUser, type MockIdp, OidcError } from "./mock-idp";
import { decodeIdTokenUnsafe, verifyIdToken } from "./oidc-crypto";
import { type PkcePair, createPkcePair } from "./pkce";
import { randomUrlToken } from "./random";
import type { Defenses } from "./types";

export const CLIENT_ID = "demo-web-client";
export const REDIRECT_URI = "https://rp.example.com/callback";
export const SCOPE = "openid profile email";

export type Actor = "browser" | "rp" | "idp";

export interface FlowStep {
  actor: Actor;
  title: string;
  detail: string;
  /** 表示用の主要パラメータ(未設定=その防御が OFF)。 */
  data?: Record<string, string | undefined>;
  /** 防御が働いたステップかどうか(ハイライト用)。 */
  guarded?: boolean;
}

export interface FlowResult {
  ok: boolean;
  steps: FlowStep[];
  loggedInAs?: EndUser;
  claims?: Record<string, unknown>;
  idToken?: string;
  error?: string;
}

/** 認可コードフロー + PKCE を 1 回実行し、ステップ列と結果を返す。 */
export async function runAuthCodeFlow(
  idp: MockIdp,
  defenses: Defenses,
  user: EndUser,
): Promise<FlowResult> {
  const steps: FlowStep[] = [];

  // --- RP: セッション秘密の生成 ---
  const state = defenses.state ? randomUrlToken(16) : undefined;
  const nonce = defenses.nonce ? randomUrlToken(16) : undefined;
  const pkce: PkcePair | undefined = defenses.pkce ? await createPkcePair("S256") : undefined;

  steps.push({
    actor: "rp",
    title: "① RP がセッション秘密を生成",
    detail:
      "ログイン開始時に、RP はブラウザセッションに紐づく使い捨ての値を作る。" +
      "OFF の防御に対応する値は生成されない。",
    data: {
      state: state ?? "(生成しない)",
      nonce: nonce ?? "(生成しない)",
      code_challenge: pkce ? `${pkce.challenge.slice(0, 16)}… (S256)` : "(生成しない)",
    },
    guarded: defenses.state || defenses.nonce || defenses.pkce,
  });

  try {
    // --- ブラウザ → IdP: 認可リクエスト ---
    steps.push({
      actor: "browser",
      title: "② 認可リクエストで IdP へリダイレクト",
      detail: "ブラウザが authorize エンドポイントへ遷移する。",
      data: {
        response_type: "code",
        client_id: CLIENT_ID,
        redirect_uri: REDIRECT_URI,
        scope: SCOPE,
        state,
        nonce,
        code_challenge: pkce?.challenge,
        code_challenge_method: pkce ? "S256" : undefined,
      },
    });

    // --- IdP: 認証 + 認可コード発行 ---
    const authz = idp.authorize(
      {
        responseType: "code",
        clientId: CLIENT_ID,
        redirectUri: REDIRECT_URI,
        scope: SCOPE,
        state,
        nonce,
        codeChallenge: pkce?.challenge,
        codeChallengeMethod: pkce ? "S256" : undefined,
      },
      user,
    );
    steps.push({
      actor: "idp",
      title: "③ IdP がログインさせ、認可コードを発行",
      detail: `${user.name} を認証し、認可コードを redirect_uri へ返す。state はそのままエコーバックされる。`,
      data: { code: `${authz.code.slice(0, 12)}…`, state: authz.state },
    });

    // --- RP: コールバックで state 照合 ---
    if (defenses.state) {
      if (authz.state !== state) {
        steps.push({
          actor: "rp",
          title: "④ state 照合に失敗 → 中断",
          detail:
            "返ってきた state がセッションの値と一致しない。CSRF/コード注入の疑いとして拒否する。",
          guarded: true,
        });
        return { ok: false, steps, error: "state mismatch" };
      }
      steps.push({
        actor: "rp",
        title: "④ コールバックの state を照合 ✓",
        detail: "返ってきた state がセッションの値と一致。CSRF/コード注入でないことを確認。",
        data: { received: authz.state, expected: state },
        guarded: true,
      });
    } else {
      steps.push({
        actor: "rp",
        title: "④ state 照合をスキップ",
        detail: "state 防御が OFF。コールバックの出所を確認せずに次へ進む。",
      });
    }

    // --- RP → IdP: トークン交換 ---
    const tokens = await idp.token({
      grantType: "authorization_code",
      code: authz.code,
      clientId: CLIENT_ID,
      redirectUri: REDIRECT_URI,
      codeVerifier: pkce?.verifier,
    });
    steps.push({
      actor: "rp",
      title: "⑤ 認可コードをトークンに交換",
      detail: pkce
        ? "token エンドポイントに code と code_verifier を送る。IdP が PKCE を検証する。"
        : "token エンドポイントに code を送る(PKCE なし)。",
      data: {
        code_verifier: pkce ? `${pkce.verifier.slice(0, 16)}…` : "(送らない)",
        id_token: `${tokens.idToken.slice(0, 24)}…`,
        access_token: `${tokens.accessToken.slice(0, 12)}…`,
      },
      guarded: defenses.pkce,
    });

    // --- RP: id_token 検証 ---
    let claims: Record<string, unknown>;
    if (defenses.idTokenValidation) {
      const result = await verifyIdToken(tokens.idToken, idp.jwks(), {
        issuer: idp.issuer,
        audience: CLIENT_ID,
      });
      if (!result.valid || !result.payload) {
        steps.push({
          actor: "rp",
          title: "⑥ id_token 検証に失敗 → 中断",
          detail: result.error ?? "検証に失敗しました。",
          guarded: true,
        });
        return { ok: false, steps, error: result.error };
      }
      // nonce 照合(リプレイ対策)。
      if (defenses.nonce && result.payload.nonce !== nonce) {
        steps.push({
          actor: "rp",
          title: "⑥ nonce 不一致 → 中断",
          detail: "id_token の nonce がセッションの値と一致しない。リプレイの疑いとして拒否する。",
          guarded: true,
        });
        return { ok: false, steps, error: "nonce mismatch" };
      }
      claims = result.payload;
      steps.push({
        actor: "rp",
        title: "⑥ id_token を JWKS で検証 ✓",
        detail: `署名・iss・aud・exp を検証${
          defenses.nonce ? "し、nonce の一致も確認" : "(nonce 照合は OFF)"
        }。クレームを信頼できる。`,
        data: {
          sub: String(claims.sub),
          iss: String(claims.iss),
          aud: String(claims.aud),
          nonce: claims.nonce ? String(claims.nonce) : undefined,
        },
        guarded: true,
      });
    } else {
      // 検証せずにデコードするだけ(危険)。
      claims = decodeIdTokenUnsafe(tokens.idToken);
      steps.push({
        actor: "rp",
        title: "⑥ id_token を検証せずデコード",
        detail: "id_token 検証が OFF。署名を確認せず、クレームをそのまま信用してしまう。",
        data: { sub: String(claims.sub) },
      });
    }

    // --- RP → IdP: UserInfo ---
    const profile = idp.userInfo(tokens.accessToken);
    steps.push({
      actor: "idp",
      title: "⑦ UserInfo でプロフィール取得",
      detail: "access_token を提示してユーザー情報を得る。ログイン完了。",
      data: { sub: profile.sub, name: profile.name, email: profile.email },
    });

    return { ok: true, steps, loggedInAs: profile, claims, idToken: tokens.idToken };
  } catch (err) {
    const message = err instanceof OidcError ? `${err.code}: ${err.message}` : String(err);
    steps.push({ actor: "idp", title: "エラー", detail: message, guarded: true });
    return { ok: false, steps, error: message };
  }
}
