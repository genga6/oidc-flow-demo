import { OidcDemo } from "./components/OidcDemo";

export function App() {
  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">
      <div className="mx-auto max-w-4xl px-5 py-10">
        <header className="mb-8">
          <h1 className="text-3xl font-bold tracking-tight">OIDC 認可コードフロー + PKCE デモ</h1>
          <p className="mt-3 max-w-2xl text-slate-400">
            OpenID Connect の認可コードフロー + PKCE を、ブラウザ内で動くモック IdP
            で再現する。state / nonce / PKCE / id_token 検証の各防御をトグルで OFF
            にすると、対応する攻撃（CSRF・コード注入 / リプレイ / コード横取り /
            偽造トークン）が成立する様子を確認できる。
          </p>
          <p className="mt-3 max-w-2xl text-sm text-slate-500">
            姉妹デモ{" "}
            <a
              href="https://github.com/genga6/jwt-tampering-demo"
              className="text-indigo-400 hover:underline"
              target="_blank"
              rel="noreferrer"
            >
              jwt-tampering-demo
            </a>{" "}
            が id_token 単体の署名検証を扱うのに対し、こちらはその id_token をやり取りする OIDC
            フロー全体とその防御機構を扱う。
          </p>
        </header>

        <main>
          <OidcDemo />
        </main>

        <footer className="mt-12 border-t border-slate-800 pt-6 text-sm text-slate-500">
          モック IdP の署名 / 鍵生成 / id_token 検証は{" "}
          <a
            href="https://github.com/panva/jose"
            className="text-indigo-400 hover:underline"
            target="_blank"
            rel="noreferrer"
          >
            jose
          </a>{" "}
          によりブラウザの Web Crypto 上で実行。実在の IdP
          には接続せず、鍵はこのタブから外に出ない。
        </footer>
      </div>
    </div>
  );
}
