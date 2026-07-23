/**
 * OIDC 認可コードフロー + PKCE デモ本体。
 *
 * 4 つの防御(state / nonce / PKCE / id_token 検証)をトグルで切り替えると:
 *   - 上段: 正常フローの各ステップ表示が、その防御の有無に応じて変化する
 *   - 下段: 対応する攻撃が「成立」か「阻止」かに切り替わる
 *
 * すべてブラウザ内で完結し、モック IdP と RP のやり取りをその場で再計算する。
 */
import { useEffect, useState } from "react";
import {
  type AttackOutcome,
  attackCodeInterception,
  attackCsrfCodeInjection,
  attackForgedIdToken,
  attackIdTokenReplay,
} from "../lib/attacks";
import { MockIdp, USERS } from "../lib/mock-idp";
import { CLIENT_ID, type FlowResult, REDIRECT_URI, runAuthCodeFlow } from "../lib/relying-party";
import { DEFENSE_KEYS, type DefenseKey, type Defenses } from "../lib/types";
import { ActorBadge, AttackStatus, Card, DataGrid, Toggle } from "./ui";

const DEFENSE_META: Record<DefenseKey, { label: string; hint: string }> = {
  state: { label: "state", hint: "コールバックの出所を照合する（CSRF / コード注入対策）" },
  nonce: { label: "nonce", hint: "id_token を今回のログインに束縛する（リプレイ対策）" },
  pkce: { label: "PKCE", hint: "認可コードをクライアントに束縛する（横取り対策）" },
  idTokenValidation: {
    label: "id_token 検証",
    hint: "JWKS で署名と iss/aud/exp を検証する（偽造対策）",
  },
};

interface AttackSpec {
  key: DefenseKey;
  title: string;
  when: string;
  run: (idp: MockIdp, enabled: boolean) => Promise<AttackOutcome>;
}

const ATTACKS: AttackSpec[] = [
  {
    key: "state",
    title: "CSRF / 認可コード注入",
    when: "state を無効化すると成立",
    run: attackCsrfCodeInjection,
  },
  {
    key: "nonce",
    title: "id_token リプレイ",
    when: "nonce を無効化すると成立",
    run: attackIdTokenReplay,
  },
  {
    key: "pkce",
    title: "認可コード横取り",
    when: "PKCE を無効化すると成立",
    run: attackCodeInterception,
  },
  {
    key: "idTokenValidation",
    title: "偽造 id_token の受理",
    when: "id_token 検証を無効化すると成立",
    run: attackForgedIdToken,
  },
];

export function OidcDemo() {
  const [idp, setIdp] = useState<MockIdp | null>(null);
  const [defenses, setDefenses] = useState<Defenses>({
    state: true,
    nonce: true,
    pkce: true,
    idTokenValidation: true,
  });
  const [flow, setFlow] = useState<FlowResult | null>(null);
  const [outcomes, setOutcomes] = useState<Partial<Record<DefenseKey, AttackOutcome>>>({});

  // モック IdP を起動（鍵ペア生成）。
  useEffect(() => {
    let alive = true;
    MockIdp.create({ clientId: CLIENT_ID, redirectUris: [REDIRECT_URI] }).then((created) => {
      if (alive) setIdp(created);
    });
    return () => {
      alive = false;
    };
  }, []);

  // 正常フローを再計算。
  useEffect(() => {
    if (!idp) return;
    let alive = true;
    runAuthCodeFlow(idp, defenses, USERS.alice).then((result) => {
      if (alive) setFlow(result);
    });
    return () => {
      alive = false;
    };
  }, [idp, defenses]);

  // 各攻撃を再計算。
  useEffect(() => {
    if (!idp) return;
    let alive = true;
    Promise.all(ATTACKS.map((a) => a.run(idp, defenses[a.key]))).then((results) => {
      if (!alive) return;
      const next: Partial<Record<DefenseKey, AttackOutcome>> = {};
      ATTACKS.forEach((a, i) => {
        next[a.key] = results[i];
      });
      setOutcomes(next);
    });
    return () => {
      alive = false;
    };
  }, [idp, defenses]);

  const setDefense = (key: DefenseKey, value: boolean) =>
    setDefenses((prev) => ({ ...prev, [key]: value }));

  const allOn = DEFENSE_KEYS.every((k) => defenses[k]);
  const allOff = DEFENSE_KEYS.every((k) => !defenses[k]);

  return (
    <div className="space-y-6">
      {/* 防御トグル */}
      <Card
        title="防御スイッチ"
        subtitle="各防御を OFF にすると、下の対応する攻撃が成立する。既定は全部 ON（安全）。"
      >
        <div className="mb-3 flex gap-2">
          <button
            type="button"
            onClick={() =>
              setDefenses({ state: true, nonce: true, pkce: true, idTokenValidation: true })
            }
            disabled={allOn}
            className="rounded-lg bg-slate-700/70 px-3 py-1.5 text-xs font-medium text-slate-100 transition hover:bg-slate-600/80 disabled:opacity-40"
          >
            すべて ON
          </button>
          <button
            type="button"
            onClick={() =>
              setDefenses({ state: false, nonce: false, pkce: false, idTokenValidation: false })
            }
            disabled={allOff}
            className="rounded-lg bg-slate-700/70 px-3 py-1.5 text-xs font-medium text-slate-100 transition hover:bg-slate-600/80 disabled:opacity-40"
          >
            すべて OFF
          </button>
        </div>
        <div className="grid gap-2 sm:grid-cols-2">
          {DEFENSE_KEYS.map((key) => (
            <Toggle
              key={key}
              checked={defenses[key]}
              onChange={(v) => setDefense(key, v)}
              label={DEFENSE_META[key].label}
              hint={DEFENSE_META[key].hint}
            />
          ))}
        </div>
      </Card>

      {/* 正常フローの可視化 */}
      <Card
        title="① 正常フロー（ブラウザ / RP / IdP）"
        subtitle="Alice のログインを段階表示。ON の防御はチェックとして現れ、OFF ならその手順が省かれる。"
      >
        <FlowTrace flow={flow} />
      </Card>

      {/* 攻撃マトリクス */}
      <Card
        title="② 防御を外すと成立する攻撃"
        subtitle="上のトグルと連動。ON なら「防御で阻止」、OFF なら「攻撃成立」に変わる。"
      >
        <div className="grid gap-4 lg:grid-cols-2">
          {ATTACKS.map((a) => (
            <AttackCard
              key={a.key}
              spec={a}
              enabled={defenses[a.key]}
              outcome={outcomes[a.key]}
              onToggle={(v) => setDefense(a.key, v)}
            />
          ))}
        </div>
      </Card>
    </div>
  );
}

function FlowTrace({ flow }: { flow: FlowResult | null }) {
  if (!flow) return <p className="text-sm text-slate-500">計算中…</p>;
  return (
    <div>
      <ol className="space-y-2">
        {flow.steps.map((step, i) => (
          <li
            key={`${step.title}-${i}`}
            className={`rounded-lg p-3 ring-1 ${
              step.guarded ? "bg-indigo-500/5 ring-indigo-500/30" : "bg-slate-950/40 ring-slate-800"
            }`}
          >
            <div className="flex flex-wrap items-center gap-2">
              <ActorBadge actor={step.actor} />
              <span className="text-sm font-medium text-slate-200">{step.title}</span>
            </div>
            <p className="mt-1 text-xs leading-relaxed text-slate-400">{step.detail}</p>
            {step.data && <DataGrid data={step.data} />}
          </li>
        ))}
      </ol>
      <div
        className={`mt-4 rounded-lg p-3 text-sm font-medium ring-1 ${
          flow.ok
            ? "bg-emerald-500/10 text-emerald-200 ring-emerald-500/40"
            : "bg-rose-500/10 text-rose-200 ring-rose-500/40"
        }`}
      >
        {flow.ok
          ? `ログイン成功: ${flow.loggedInAs?.name}（sub=${flow.loggedInAs?.sub}）`
          : `フロー中断: ${flow.error ?? "不明なエラー"}`}
      </div>
    </div>
  );
}

function AttackCard({
  spec,
  enabled,
  outcome,
  onToggle,
}: {
  spec: AttackSpec;
  enabled: boolean;
  outcome?: AttackOutcome;
  onToggle: (next: boolean) => void;
}) {
  return (
    <div className="flex flex-col gap-3 rounded-xl bg-slate-950/40 p-4 ring-1 ring-slate-800">
      <div className="flex items-start justify-between gap-3">
        <div>
          <h3 className="font-semibold text-slate-100">{spec.title}</h3>
          <p className="text-xs text-slate-500">{spec.when}</p>
        </div>
        {outcome ? <AttackStatus succeeded={outcome.attackSucceeded} /> : null}
      </div>

      <label className="flex items-center gap-2 text-xs text-slate-400">
        <input
          type="checkbox"
          checked={enabled}
          onChange={(e) => onToggle(e.target.checked)}
          className="h-4 w-4 accent-emerald-500"
        />
        防御「{DEFENSE_META[spec.key].label}」: {enabled ? "ON" : "OFF"}
      </label>

      {outcome && (
        <>
          <p className="text-sm text-slate-300">{outcome.summary}</p>
          <p className="text-xs leading-relaxed text-slate-500">{outcome.detail}</p>
          {outcome.evidence && <DataGrid data={outcome.evidence} />}
        </>
      )}
    </div>
  );
}
