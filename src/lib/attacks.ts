/**
 * 攻撃シミュレーション。
 *
 * 各防御を 1 つずつ主役にし、「ON なら阻止 / OFF なら成立」を再現する。
 * 他の防御に依存せず、対応する防御 1 つだけで結果が決まるように構成している
 * (姉妹デモ jwt-tampering-demo の「方式を切り替えると結果が変わる」思想を踏襲)。
 */
import { type EndUser, type MockIdp, OidcError, USERS } from "./mock-idp";
import { createSigningKey, decodeIdTokenUnsafe, signIdToken, verifyIdToken } from "./oidc-crypto";
import { createPkcePair } from "./pkce";
import { randomUrlToken } from "./random";
import { CLIENT_ID, REDIRECT_URI, SCOPE } from "./relying-party";

export interface AttackOutcome {
  /** 攻撃が成立してしまったか(true = 危険)。 */
  attackSucceeded: boolean;
  /** 防御が働いて阻止できたか。 */
  defended: boolean;
  /** 一行サマリ。 */
  summary: string;
  /** 詳細説明。 */
  detail: string;
  /** 画面表示用の証拠(結果を裏づける値)。 */
  evidence?: Record<string, string>;
}

const authorizeParams = (
  extra: Partial<{
    state: string;
    nonce: string;
    codeChallenge: string;
  }> = {},
) => ({
  responseType: "code",
  clientId: CLIENT_ID,
  redirectUri: REDIRECT_URI,
  scope: SCOPE,
  ...extra,
});

/**
 * 攻撃 1: CSRF / 認可コード注入（防御: state）。
 *
 * 攻撃者は自分(Mallory)のアカウントの認可コードを取得し、それを被害者の
 * コールバックに注入する。RP が state を照合しなければ、被害者のセッションは
 * 攻撃者アカウントでログインさせられる(被害者の操作が攻撃者の口座に紐づく)。
 */
export async function attackCsrfCodeInjection(
  idp: MockIdp,
  stateEnabled: boolean,
): Promise<AttackOutcome> {
  // 被害者 RP はログインを開始し、state をセッションに保存(防御 ON のとき)。
  const victimState = stateEnabled ? randomUrlToken(16) : undefined;

  // 攻撃者は自分のアカウントの認可コードを正規に取得しておく。
  const attackerAuthz = idp.authorize(authorizeParams({ state: "attacker-chosen" }), USERS.mallory);

  // 攻撃者は被害者のブラウザにこのコードを注入する。state は攻撃者の値(被害者の値は知らない)。
  const injectedState = "attacker-chosen";

  if (stateEnabled && injectedState !== victimState) {
    return {
      attackSucceeded: false,
      defended: true,
      summary: "state 不一致で注入コールバックを拒否",
      detail:
        "RP は注入された state が自セッションの state と違うことを検出し、コールバックを破棄する。" +
        "攻撃者は被害者の state を知り得ないため、注入は成立しない。",
      evidence: {
        "セッションの state": victimState ?? "(なし)",
        "注入された state": injectedState,
        判定: "不一致 → 拒否",
      },
    };
  }

  // state 照合なし → 注入コードをそのまま交換してしまう。
  const tokens = await idp.token({
    grantType: "authorization_code",
    code: attackerAuthz.code,
    clientId: CLIENT_ID,
    redirectUri: REDIRECT_URI,
  });
  const claims = decodeIdTokenUnsafe(tokens.idToken);
  return {
    attackSucceeded: true,
    defended: false,
    summary: "被害者セッションが攻撃者アカウントでログイン",
    detail:
      "state 照合が無いため、RP は攻撃者が注入した認可コードを受理してしまう。" +
      "被害者はそれと気づかず攻撃者(Mallory)のアカウントを操作し、入力データが攻撃者に渡る。",
    evidence: {
      "被害者が紐づいた sub": String(claims.sub),
      期待されるユーザー: USERS.alice.sub,
    },
  };
}

/**
 * 攻撃 2: id_token リプレイ（防御: nonce）。
 *
 * 攻撃者は過去に発行された正規の id_token を捕捉し、新しいログイン応答として
 * 使い回す。署名は本物なので署名検証は通る — nonce の照合だけがリプレイを弾く。
 */
export async function attackIdTokenReplay(
  idp: MockIdp,
  nonceEnabled: boolean,
): Promise<AttackOutcome> {
  // 過去のログイン: 攻撃者はここで発行された id_token を捕捉したとする。
  const oldNonce = nonceEnabled ? randomUrlToken(16) : undefined;
  const oldAuthz = idp.authorize(authorizeParams(oldNonce ? { nonce: oldNonce } : {}), USERS.alice);
  const oldTokens = await idp.token({
    grantType: "authorization_code",
    code: oldAuthz.code,
    clientId: CLIENT_ID,
    redirectUri: REDIRECT_URI,
  });
  const capturedIdToken = oldTokens.idToken;

  // 新しいセッション: RP は新しい nonce を生成(防御 ON のとき)。
  const freshNonce = nonceEnabled ? randomUrlToken(16) : undefined;

  // 攻撃者は正規の交換を行わず、捕捉した id_token をそのまま提示する。
  const result = await verifyIdToken(capturedIdToken, idp.jwks(), {
    issuer: idp.issuer,
    audience: CLIENT_ID,
  });
  // 本物の署名なので検証自体は成功する。
  const tokenNonce = result.payload?.nonce ? String(result.payload.nonce) : undefined;

  if (nonceEnabled && tokenNonce !== freshNonce) {
    return {
      attackSucceeded: false,
      defended: true,
      summary: "nonce 不一致でリプレイを検出",
      detail:
        "署名は本物でも、id_token の nonce は過去セッションのもの。RP は今回のセッションで生成した " +
        "nonce と一致しないことを検出し、リプレイとして拒否する。",
      evidence: {
        "トークンの nonce": tokenNonce ?? "(なし)",
        "今回セッションの nonce": freshNonce ?? "(なし)",
        署名検証: "成功(本物のトークン)",
        判定: "nonce 不一致 → 拒否",
      },
    };
  }

  return {
    attackSucceeded: true,
    defended: false,
    summary: "使い回した id_token がそのまま受理される",
    detail:
      "nonce 照合が無いため、RP は過去に発行された id_token を「今回のログイン結果」として受理する。" +
      "攻撃者は本物の署名付きトークンを再送するだけでなりすませる。",
    evidence: {
      "受理した sub": String(result.payload?.sub),
      署名検証: "成功(本物のトークン)",
      nonce照合: "なし",
    },
  };
}

/**
 * 攻撃 3: 認可コード横取り（防御: PKCE）。
 *
 * 攻撃者はリダイレクト漏洩などで認可コードを横取りし、token 交換を試みる。
 * PKCE があると code_verifier を提示できず交換に失敗する。
 */
export async function attackCodeInterception(
  idp: MockIdp,
  pkceEnabled: boolean,
): Promise<AttackOutcome> {
  const pkce = pkceEnabled ? await createPkcePair("S256") : undefined;

  // 被害者 RP の認可リクエスト(PKCE ON なら code_challenge を載せる)。
  const authz = idp.authorize(
    authorizeParams(pkce ? { codeChallenge: pkce.challenge } : {}),
    USERS.alice,
  );

  // 攻撃者はこの認可コードを横取りした。verifier は知らないので付けずに交換を試みる。
  try {
    const tokens = await idp.token({
      grantType: "authorization_code",
      code: authz.code,
      clientId: CLIENT_ID,
      redirectUri: REDIRECT_URI,
    });
    const profile = idp.userInfo(tokens.accessToken);
    return {
      attackSucceeded: true,
      defended: false,
      summary: "横取りしたコードだけでトークンを取得",
      detail:
        "PKCE が無いと、認可コードは「持っていれば交換できる」ただの引換券になる。" +
        "攻撃者は横取りしたコードで id_token / access_token を入手し、被害者になりすませる。",
      evidence: {
        "取得したトークンの sub": profile.sub,
        "提示した code_verifier": "なし(不要だった)",
      },
    };
  } catch (err) {
    const message = err instanceof OidcError ? `${err.code}: ${err.message}` : String(err);
    return {
      attackSucceeded: false,
      defended: true,
      summary: "code_verifier が無く交換に失敗",
      detail:
        "IdP は authorize 時の code_challenge と一致する code_verifier を要求する。" +
        "攻撃者は verifier を知らないため、コードを横取りしても交換できない。",
      evidence: {
        "横取りした code": `${authz.code.slice(0, 12)}…`,
        "提示した code_verifier": "なし(知り得ない)",
        "IdP の応答": message,
      },
    };
  }
}

/**
 * 攻撃 4: 偽造 id_token の受理（防御: id_token 署名/クレーム検証）。
 *
 * 攻撃者は自前の鍵で id_token を偽造し、Alice になりすます。RP が JWKS で
 * 署名検証すれば「IdP の鍵ではない」と分かり弾かれる。検証しなければ通る。
 */
export async function attackForgedIdToken(
  idp: MockIdp,
  validationEnabled: boolean,
): Promise<AttackOutcome> {
  // 攻撃者は IdP とは無関係な自前の鍵ペアを用意する。
  const attackerKey = await createSigningKey();
  const victim: EndUser = USERS.alice;
  const forged = await signIdToken(attackerKey, {
    iss: idp.issuer,
    sub: victim.sub,
    aud: CLIENT_ID,
    name: victim.name,
    email: victim.email,
  });

  if (validationEnabled) {
    const result = await verifyIdToken(forged, idp.jwks(), {
      issuer: idp.issuer,
      audience: CLIENT_ID,
    });
    if (result.valid) {
      // 起こり得ないが、保険として成立扱い。
      return {
        attackSucceeded: true,
        defended: false,
        summary: "偽造トークンが検証を通過(想定外)",
        detail: "偽造 id_token が JWKS 検証を通ってしまった。",
      };
    }
    return {
      attackSucceeded: false,
      defended: true,
      summary: "JWKS に無い鍵の署名を拒否",
      detail:
        "RP は IdP の JWKS で署名を検証する。攻撃者の鍵は JWKS に無いため署名検証に失敗し、" +
        "偽造 id_token は受理されない。alg:none への格下げも同様に弾かれる。",
      evidence: {
        "偽造トークンの kid": `${attackerKey.kid.slice(0, 12)}…`,
        "IdP の JWKS": "攻撃者の鍵を含まない",
        検証結果: result.error ?? "失敗",
      },
    };
  }

  // 検証 OFF: 署名を確認せずクレームを信用する。
  const claims = decodeIdTokenUnsafe(forged);
  return {
    attackSucceeded: true,
    defended: false,
    summary: "署名を確認せず偽造トークンを受理",
    detail:
      "id_token 検証が無いと、RP は署名も発行元も確認しない。攻撃者は誰の名義でも自由に " +
      "id_token をでっち上げられ、任意のユーザーになりすませる。",
    evidence: {
      "なりすまし対象 sub": String(claims.sub),
      署名: "攻撃者の自前鍵(検証されない)",
    },
  };
}
