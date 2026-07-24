import { describe, expect, it } from "vitest";
import { computeS256Challenge, createPkcePair, verifyPkce } from "../src/lib/pkce";

describe("PKCE (S256)", () => {
  it("正しい code_verifier は challenge の検証に成功する", async () => {
    const { verifier, challenge, method } = await createPkcePair("S256");
    expect(method).toBe("S256");
    expect(await verifyPkce(verifier, challenge, "S256")).toBe(true);
  });

  it("誤った code_verifier は検証に失敗する", async () => {
    const { challenge } = await createPkcePair("S256");
    expect(await verifyPkce("attacker-guess", challenge, "S256")).toBe(false);
  });

  it("RFC 7636 の既知ベクトルと一致する", async () => {
    // RFC 7636 Appendix B のサンプル。
    const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const expected = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    expect(await computeS256Challenge(verifier)).toBe(expected);
  });
});
