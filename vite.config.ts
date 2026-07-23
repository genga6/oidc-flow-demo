import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// GitHub Pages 配下 (https://<user>.github.io/oidc-flow-demo/) で動くよう base を設定。
// ローカル開発では "/" を使う。
export default defineConfig(({ command }) => ({
  base: command === "build" ? "/oidc-flow-demo/" : "/",
  plugins: [react(), tailwindcss()],
  test: {
    environment: "node",
  },
}));
