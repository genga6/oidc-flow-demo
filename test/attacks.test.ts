import { describe, expect, it } from "vitest";
import {
  attackCodeInterception,
  attackCsrfCodeInjection,
  attackForgedIdToken,
  attackIdTokenReplay,
} from "../src/lib/attacks";
import { MockIdp, USERS } from "../src/lib/mock-idp";
import { CLIENT_ID, REDIRECT_URI } from "../src/lib/relying-party";

function createIdp() {
  return MockIdp.create({ clientId: CLIENT_ID, redirectUris: [REDIRECT_URI] });
}

describe("攻撃 1: CSRF / 認可コード注入 ↔ state", () => {
  it("state ON なら注入は阻止される", async () => {
    const out = await attackCsrfCodeInjection(await createIdp(), true);
    expect(out.defended).toBe(true);
    expect(out.attackSucceeded).toBe(false);
  });

  it("state OFF なら被害者が攻撃者アカウントでログインさせられる", async () => {
    const out = await attackCsrfCodeInjection(await createIdp(), false);
    expect(out.attackSucceeded).toBe(true);
    expect(out.evidence?.["被害者が紐づいた sub"]).toBe(USERS.mallory.sub);
  });
});

describe("攻撃 2: id_token リプレイ ↔ nonce", () => {
  it("nonce ON ならリプレイは検出される", async () => {
    const out = await attackIdTokenReplay(await createIdp(), true);
    expect(out.defended).toBe(true);
    expect(out.attackSucceeded).toBe(false);
  });

  it("nonce OFF なら使い回した id_token が受理される", async () => {
    const out = await attackIdTokenReplay(await createIdp(), false);
    expect(out.attackSucceeded).toBe(true);
  });
});

describe("攻撃 3: 認可コード横取り ↔ PKCE", () => {
  it("PKCE ON なら verifier が無く交換できない", async () => {
    const out = await attackCodeInterception(await createIdp(), true);
    expect(out.defended).toBe(true);
    expect(out.attackSucceeded).toBe(false);
  });

  it("PKCE OFF なら横取りしたコードだけで交換できる", async () => {
    const out = await attackCodeInterception(await createIdp(), false);
    expect(out.attackSucceeded).toBe(true);
    expect(out.evidence?.["取得したトークンの sub"]).toBe(USERS.alice.sub);
  });
});

describe("攻撃 4: 偽造 id_token ↔ id_token 検証", () => {
  it("検証 ON なら JWKS に無い鍵の署名が弾かれる", async () => {
    const out = await attackForgedIdToken(await createIdp(), true);
    expect(out.defended).toBe(true);
    expect(out.attackSucceeded).toBe(false);
  });

  it("検証 OFF なら偽造トークンで任意ユーザーになりすませる", async () => {
    const out = await attackForgedIdToken(await createIdp(), false);
    expect(out.attackSucceeded).toBe(true);
    expect(out.evidence?.["なりすまし対象 sub"]).toBe(USERS.alice.sub);
  });
});
