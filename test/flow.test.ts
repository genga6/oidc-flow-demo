import { describe, expect, it } from "vitest";
import { MockIdp, USERS } from "../src/lib/mock-idp";
import { CLIENT_ID, REDIRECT_URI, runAuthCodeFlow } from "../src/lib/relying-party";
import type { Defenses } from "../src/lib/types";

const ALL_ON: Defenses = { state: true, nonce: true, pkce: true, idTokenValidation: true };
const ALL_OFF: Defenses = { state: false, nonce: false, pkce: false, idTokenValidation: false };

function createIdp() {
  return MockIdp.create({ clientId: CLIENT_ID, redirectUris: [REDIRECT_URI] });
}

describe("認可コードフロー + PKCE (正常系)", () => {
  it("全防御 ON でも Alice のログインは成功する", async () => {
    const idp = await createIdp();
    const result = await runAuthCodeFlow(idp, ALL_ON, USERS.alice);
    expect(result.ok).toBe(true);
    expect(result.loggedInAs?.sub).toBe(USERS.alice.sub);
    expect(result.claims?.sub).toBe(USERS.alice.sub);
  });

  it("全防御 OFF でも正常系フロー自体は成立する（防御が薄いだけ）", async () => {
    const idp = await createIdp();
    const result = await runAuthCodeFlow(idp, ALL_OFF, USERS.alice);
    expect(result.ok).toBe(true);
    expect(result.loggedInAs?.sub).toBe(USERS.alice.sub);
  });
});

describe("IdP の基本チェック", () => {
  it("認可コードは一度しか使えない", async () => {
    const idp = await createIdp();
    const authz = idp.authorize(
      { responseType: "code", clientId: CLIENT_ID, redirectUri: REDIRECT_URI, scope: "openid" },
      USERS.alice,
    );
    await idp.token({
      grantType: "authorization_code",
      code: authz.code,
      clientId: CLIENT_ID,
      redirectUri: REDIRECT_URI,
    });
    await expect(
      idp.token({
        grantType: "authorization_code",
        code: authz.code,
        clientId: CLIENT_ID,
        redirectUri: REDIRECT_URI,
      }),
    ).rejects.toThrow();
  });

  it("未登録の redirect_uri は authorize で拒否される", async () => {
    const idp = await createIdp();
    expect(() =>
      idp.authorize(
        {
          responseType: "code",
          clientId: CLIENT_ID,
          redirectUri: "https://evil.example/callback",
          scope: "openid",
        },
        USERS.alice,
      ),
    ).toThrow();
  });
});
