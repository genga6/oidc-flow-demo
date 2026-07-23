/** デモ全体で使う小さな表示部品。 */
import type { ReactNode } from "react";
import type { Actor } from "../lib/relying-party";

/** 成立(危険)/阻止(安全) を示すバッジ。 */
export function AttackStatus({ succeeded }: { succeeded: boolean }) {
  const cls = succeeded
    ? "bg-rose-500/15 text-rose-300 ring-rose-500/40"
    : "bg-emerald-500/15 text-emerald-300 ring-emerald-500/40";
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full px-3 py-1 text-sm font-medium ring-1 ${cls}`}
    >
      <span aria-hidden>{succeeded ? "⚠" : "✓"}</span>
      {succeeded ? "攻撃成立" : "防御で阻止"}
    </span>
  );
}

const ACTOR_STYLE: Record<Actor, { label: string; cls: string }> = {
  browser: { label: "ブラウザ", cls: "bg-amber-500/15 text-amber-300 ring-amber-500/40" },
  rp: { label: "RP (クライアント)", cls: "bg-sky-500/15 text-sky-300 ring-sky-500/40" },
  idp: { label: "IdP (認可サーバー)", cls: "bg-violet-500/15 text-violet-300 ring-violet-500/40" },
};

/** どのアクターの処理かを示すバッジ。 */
export function ActorBadge({ actor }: { actor: Actor }) {
  const { label, cls } = ACTOR_STYLE[actor];
  return (
    <span
      className={`inline-flex shrink-0 items-center rounded-md px-2 py-0.5 text-xs font-semibold ring-1 ${cls}`}
    >
      {label}
    </span>
  );
}

/** ラベル + 値のキー/バリュー表示（フロー各ステップのパラメータ用）。 */
export function DataGrid({ data }: { data: Record<string, string | undefined> }) {
  const entries = Object.entries(data);
  if (entries.length === 0) return null;
  return (
    <dl className="mt-2 grid grid-cols-[max-content_1fr] gap-x-3 gap-y-1 text-[12px]">
      {entries.map(([k, v]) => (
        <div key={k} className="contents">
          <dt className="font-mono text-slate-500">{k}</dt>
          <dd className={`break-all font-mono ${v ? "text-slate-300" : "text-slate-600"}`}>
            {v ?? "—"}
          </dd>
        </div>
      ))}
    </dl>
  );
}

/** ラベル付きのカード枠。 */
export function Card({
  title,
  subtitle,
  children,
}: {
  title: ReactNode;
  subtitle?: ReactNode;
  children: ReactNode;
}) {
  return (
    <section className="rounded-2xl bg-slate-900/60 p-6 ring-1 ring-slate-700/60 backdrop-blur">
      <h2 className="text-lg font-semibold text-slate-100">{title}</h2>
      {subtitle && <p className="mt-1 mb-4 text-sm leading-relaxed text-slate-400">{subtitle}</p>}
      {children}
    </section>
  );
}

/** 防御の ON/OFF トグルスイッチ。 */
export function Toggle({
  checked,
  onChange,
  label,
  hint,
}: {
  checked: boolean;
  onChange: (next: boolean) => void;
  label: string;
  hint: string;
}) {
  return (
    <button
      type="button"
      onClick={() => onChange(!checked)}
      className={`flex w-full items-start gap-3 rounded-xl border p-3 text-left transition ${
        checked ? "border-emerald-500/40 bg-emerald-500/10" : "border-rose-500/40 bg-rose-500/10"
      }`}
    >
      <span
        aria-hidden
        className={`mt-0.5 flex h-5 w-9 shrink-0 items-center rounded-full p-0.5 transition ${
          checked ? "bg-emerald-500/80" : "bg-slate-600"
        }`}
      >
        <span
          className={`h-4 w-4 rounded-full bg-white transition ${checked ? "translate-x-4" : ""}`}
        />
      </span>
      <span className="min-w-0">
        <span className="flex items-center gap-2">
          <span className="font-medium text-slate-100">{label}</span>
          <span
            className={`text-[11px] font-bold ${checked ? "text-emerald-300" : "text-rose-300"}`}
          >
            {checked ? "ON" : "OFF"}
          </span>
        </span>
        <span className="mt-0.5 block text-xs text-slate-400">{hint}</span>
      </span>
    </button>
  );
}

/** ラベル付きの JSON/テキスト表示パネル。 */
export function CodePanel({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <div className="mb-1 text-xs font-semibold uppercase tracking-wide text-slate-400">
        {label}
      </div>
      <pre className="max-h-64 overflow-auto rounded-lg bg-slate-950/70 p-3 font-mono text-[12px] leading-relaxed text-slate-200 ring-1 ring-slate-700">
        {value}
      </pre>
    </div>
  );
}
