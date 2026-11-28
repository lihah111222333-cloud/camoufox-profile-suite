// SPDX-License-Identifier: AGPL-3.0-or-later
// Camoufox Studio — Local API Key, CLI Access, Live Tester & External Service Keys

import { useCallback, useEffect, useState } from "react";
import {
  api,
  type Profile,
  type SuiteCliInfo,
  type SuiteCliRunResult,
  type SuiteSecretKeys,
} from "../../api";

type SnippetLang = "curl" | "cli" | "node" | "python";

export function ApiCliView({
  isZh,
  profiles,
}: {
  isZh: boolean;
  profiles: Profile[];
}) {
  const [info, setInfo] = useState<SuiteCliInfo | null>(null);
  const [keys, setKeys] = useState<SuiteSecretKeys | null>(null);
  const [keyDraft, setKeyDraft] = useState<Record<string, string>>({});
  const [showLocalKey, setShowLocalKey] = useState(false);
  const [revealedKeys, setRevealedKeys] = useState<Set<string>>(new Set());
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [snippetTab, setSnippetTab] = useState<SnippetLang>("curl");

  const [rotating, setRotating] = useState(false);
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<{
    ok: boolean;
    status: number;
    ms: number;
    body: string;
  } | null>(null);

  const [cliBusy, setCliBusy] = useState<string | null>(null);
  const [cliOutput, setCliOutput] = useState<SuiteCliRunResult | null>(null);

  const [keysSaved, setKeysSaved] = useState(false);
  const [keysBusy, setKeysBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setError(null);
    try {
      const [cliInfo, secretKeys] = await Promise.all([
        api.suiteCliInfo(),
        api.suiteGetKeys(),
      ]);
      setInfo(cliInfo);
      setKeys(secretKeys);
      const draft: Record<string, string> = {};
      for (const item of secretKeys.items) {
        draft[item.key] = item.value;
      }
      setKeyDraft(draft);
    } catch (e: any) {
      setError(e?.message || String(e));
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const copyText = async (id: string, text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopiedId(id);
      setTimeout(() => setCopiedId((cur) => (cur === id ? null : cur)), 1800);
    } catch {
      // ignore clipboard errors
    }
  };

  const rotateKey = async () => {
    setRotating(true);
    setError(null);
    try {
      const res = await api.suiteRotateApiKey();
      setInfo((cur) =>
        cur ? { ...cur, apiKey: res.apiKey, apiKeyCreatedAt: res.apiKeyCreatedAt } : cur,
      );
      setShowLocalKey(true);
      setTestResult(null);
    } catch (e: any) {
      setError(e?.message || String(e));
    } finally {
      setRotating(false);
    }
  };

  const testApiKey = async () => {
    if (!info) return;
    setTesting(true);
    setError(null);
    const started = performance.now();
    try {
      const res = await fetch("/api/v1/profiles", {
        method: "GET",
        headers: { "X-API-Key": info.apiKey },
      });
      const json = await res.json().catch(() => null);
      setTestResult({
        ok: res.ok,
        status: res.status,
        ms: Math.round(performance.now() - started),
        body: JSON.stringify(
          json?.profiles
            ? { ok: json.ok, count: json.profiles.length, sample: json.profiles.slice(0, 2).map((p: any) => ({ id: p.id, name: p.name, persona_id: p.persona_id, running: p.running })) }
            : json,
          null,
          2,
        ),
      });
    } catch (e: any) {
      setTestResult({
        ok: false,
        status: 0,
        ms: Math.round(performance.now() - started),
        body: e?.message || String(e),
      });
    } finally {
      setTesting(false);
    }
  };

  const runCli = async (commandId: string) => {
    setCliBusy(commandId);
    setError(null);
    try {
      setCliOutput(await api.suiteRunCli(commandId));
    } catch (e: any) {
      setError(e?.message || String(e));
    } finally {
      setCliBusy(null);
    }
  };

  const saveSecretKeys = async () => {
    setKeysBusy(true);
    setKeysSaved(false);
    setError(null);
    try {
      const updated = await api.suiteSaveKeys(keyDraft);
      setKeys(updated);
      const nextDraft: Record<string, string> = {};
      for (const item of updated.items) nextDraft[item.key] = item.value;
      setKeyDraft(nextDraft);
      setKeysSaved(true);
      setTimeout(() => setKeysSaved(false), 2500);
    } catch (e: any) {
      setError(e?.message || String(e));
    } finally {
      setKeysBusy(false);
    }
  };

  const sampleProfileId = profiles[0]?.id || "camoufox-profile-id";
  const endpoint = info?.endpoint || "http://127.0.0.1:5274";
  const apiKeyDisplay = info?.apiKey
    ? showLocalKey
      ? info.apiKey
      : `${info.apiKey.slice(0, 13)}${"•".repeat(20)}${info.apiKey.slice(-4)}`
    : "—";
  const keyPlaceholder = info?.apiKey
    ? showLocalKey
      ? info.apiKey
      : "$CAMOUFOX_API_KEY"
    : "$CAMOUFOX_API_KEY";

  const snippets: Record<SnippetLang, string> = {
    curl: `# 1. ${isZh ? "导出本地 API Key 与端点" : "Export local API key & endpoint"}
export CAMOUFOX_API_URL="${endpoint}/api/v1"
export CAMOUFOX_API_KEY="${keyPlaceholder}"

# 2. ${isZh ? "查询全部环境" : "List all profiles"}
curl -sS -H "X-API-Key: $CAMOUFOX_API_KEY" "$CAMOUFOX_API_URL/profiles"

# 3. ${isZh ? "拉起指定环境的独立浏览器窗口" : "Launch isolated browser window"}
curl -sS -X POST -H "Authorization: Bearer $CAMOUFOX_API_KEY" \\
  "$CAMOUFOX_API_URL/profiles/${sampleProfileId}/launch"

# 4. ${isZh ? "关闭指定环境" : "Stop running browser window"}
curl -sS -X POST -H "Authorization: Bearer $CAMOUFOX_API_KEY" \\
  "$CAMOUFOX_API_URL/profiles/${sampleProfileId}/stop"`,

    cli: `# ${isZh ? "在项目根目录运行内置 CLI 工具" : "Run built-in CLI commands in repo root"}
cd "${info?.repoRoot || "."}"

# ${isZh ? "启动主批处理 CLI" : "Run main CLI"}
npm start -- --accounts=1 --threads=1

# ${isZh ? "运行三端 17 项硬件指纹一致性审计" : "Run 17-check cross-OS coherence audit"}
npm run verify-camoufox -- --dry-run

# ${isZh ? "列出 37 套实机 SKU 硬件预设" : "List 37 SKU-verified presets"}
node scripts/audit-adspower-profiles.js --list-presets

# ${isZh ? "查询 Pre-TLS 流量归因日志" : "Query pre-TLS traffic attribution"}
npm run audit-traffic -- --help`,

    node: `// Node.js (>=18) ${isZh ? "本地 API 调用示例" : "Local API example"}
const API = "${endpoint}/api/v1";
const KEY = process.env.CAMOUFOX_API_KEY || "${keyPlaceholder}";

const res = await fetch(\`\${API}/profiles\`, {
  headers: { Authorization: \`Bearer \${KEY}\` },
});
const { profiles } = await res.json();
console.log("Profiles:", profiles.length);

// ${isZh ? "拉起环境" : "Launch profile"}
await fetch(\`\${API}/profiles/${sampleProfileId}/launch\`, {
  method: "POST",
  headers: { "X-API-Key": KEY },
});`,

    python: `# Python (requests) ${isZh ? "本地 API 调用示例" : "Local API example"}
import os, requests

API = "${endpoint}/api/v1"
KEY = os.environ.get("CAMOUFOX_API_KEY", "${keyPlaceholder}")
HEADERS = {"X-API-Key": KEY}

profiles = requests.get(f"{API}/profiles", headers=HEADERS, timeout=10).json()["profiles"]
print(f"Found {len(profiles)} profiles")

# ${isZh ? "拉起指定环境" : "Launch profile"}
requests.post(f"{API}/profiles/${sampleProfileId}/launch", headers=HEADERS, timeout=15)`,
  };

  return (
    <div className="donut-lab">
      {error && (
        <div className="notice warnBar" role="alert" style={{ marginBottom: "var(--s-3)" }}>
          <span>{error}</span>
          <button className="linky" onClick={() => setError(null)}>×</button>
        </div>
      )}

      <div className="donut-lab-body">
        {/* Section 1: Local API Endpoint & Access Key */}
        <div className="donut-panel">
          <div className="donut-panel-head" style={{ flexWrap: "wrap", gap: 10 }}>
            <div>
              <h3>{isZh ? "本地 API 访问端点 & API Key（仅回环 127.0.0.1）" : "Local API Endpoint & Access Key"}</h3>
              <p className="muted small" style={{ margin: "2px 0 0" }}>
                {isZh
                  ? "使用 X-API-Key 或 Authorization: Bearer 鉴权，供 CLI、curl、Python、Node.js 或外部自动化脚本本地控制环境。"
                  : "Authenticate via X-API-Key or Authorization: Bearer for CLI, curl, Python, Node.js or external scripts."}
              </p>
            </div>
            <button className="primary" disabled={testing || !info} onClick={() => void testApiKey()}>
              {testing
                ? isZh ? "测试中..." : "Testing..."
                : isZh ? "测试 API Key 连通性" : "Test API Key"}
            </button>
          </div>

          <div className="api-key-grid">
            <div className="api-key-box">
              <div className="api-key-label">{isZh ? "本地 API 根地址 (REST v1)" : "Local API Base URL"}</div>
              <div className="api-key-row">
                <code className="mono api-key-value">{info?.apiBase || "—"}</code>
                <button
                  className="ghost"
                  disabled={!info}
                  onClick={() => info && void copyText("endpoint", info.apiBase)}
                >
                  {copiedId === "endpoint" ? (isZh ? "已复制" : "Copied") : (isZh ? "复制" : "Copy")}
                </button>
              </div>
              <div className="muted small" style={{ marginTop: 4 }}>
                {isZh
                  ? `模式: ${info?.desktopMode ? "原生桌面壳 (动态回环端口)" : "HTTP 控制台"} · 严格回环 Host 保护`
                  : `Mode: ${info?.desktopMode ? "Desktop App" : "HTTP Server"} · Loopback-only Host guard`}
              </div>
            </div>

            <div className="api-key-box">
              <div className="api-key-label">
                <span>Local API Key</span>
                <span className="donut-pill donut-pill-success" style={{ marginLeft: 8 }}>
                  <span className="donut-dot" />
                  0600 私有存储
                </span>
              </div>
              <div className="api-key-row">
                <code className="mono api-key-value">{apiKeyDisplay}</code>
                <button className="ghost" onClick={() => setShowLocalKey((v) => !v)}>
                  {showLocalKey ? (isZh ? "隐藏" : "Hide") : (isZh ? "显示" : "Show")}
                </button>
                <button
                  className="ghost"
                  disabled={!info}
                  onClick={() => info && void copyText("apikey", info.apiKey)}
                >
                  {copiedId === "apikey" ? (isZh ? "已复制" : "Copied") : (isZh ? "复制" : "Copy")}
                </button>
                <button className="ghost" disabled={rotating} onClick={() => void rotateKey()}>
                  {rotating ? (isZh ? "轮换中..." : "Rotating...") : (isZh ? "重新生成" : "Rotate")}
                </button>
              </div>
              <div className="muted small" style={{ marginTop: 4 }}>
                {info?.apiKeyCreatedAt
                  ? `${isZh ? "签发时间:" : "Created:"} ${new Date(info.apiKeyCreatedAt).toLocaleString()}`
                  : ""}
              </div>
            </div>
          </div>

          {testResult && (
            <div className="api-test-result">
              <div className="row" style={{ gap: 10, marginBottom: 6 }}>
                <span className={`donut-pill ${testResult.ok ? "donut-pill-success" : "donut-pill-failed"}`}>
                  <span className="donut-dot" />
                  HTTP {testResult.status} · {testResult.ok ? "OK" : "FAILED"}
                </span>
                <span className="muted small mono">{testResult.ms} ms · GET /api/v1/profiles</span>
              </div>
              <pre className="donut-console" style={{ margin: 0 }}>{testResult.body}</pre>
            </div>
          )}
        </div>

        {/* Section 2: CLI Quick Runner + Snippets + REST Endpoint Catalog */}
        <div className="donut-panel">
          <div className="donut-panel-head" style={{ flexWrap: "wrap", gap: 10 }}>
            <div>
              <h3>{isZh ? "CLI 快捷执行 & 接口调用示例" : "CLI Runner & Code Snippets"}</h3>
              <p className="muted small" style={{ margin: "2px 0 0" }}>
                {isZh
                  ? "直接运行项目内置安全诊断 CLI，或复制带当前端口和 Key 的终端命令。"
                  : "Run allowlisted project CLI diagnostics directly or copy ready-to-run snippets."}
              </p>
            </div>
            <div className="segmented">
              {(["curl", "cli", "node", "python"] as const).map((lang) => (
                <button
                  key={lang}
                  aria-pressed={snippetTab === lang}
                  onClick={() => setSnippetTab(lang)}
                >
                  {lang === "curl" ? "cURL" : lang === "cli" ? (isZh ? "项目 CLI" : "CLI") : lang === "node" ? "Node.js" : "Python"}
                </button>
              ))}
            </div>
          </div>

          <div className="api-code-wrap">
            <button
              className="ghost api-copy-float"
              onClick={() => void copyText(`snip-${snippetTab}`, snippets[snippetTab])}
            >
              {copiedId === `snip-${snippetTab}` ? (isZh ? "✓ 已复制" : "✓ Copied") : (isZh ? "复制代码" : "Copy")}
            </button>
            <pre className="donut-console" style={{ margin: 0, maxHeight: 240 }}>{snippets[snippetTab]}</pre>
          </div>

          {info && (
            <div style={{ marginTop: 14 }}>
              <div className="api-sub-title">{isZh ? "一键运行内置 CLI 命令" : "One-Click Built-in CLI Commands"}</div>
              <div className="api-cli-actions">
                {info.cliCommands.map((c) => (
                  <button
                    key={c.id}
                    className="api-cli-btn"
                    disabled={cliBusy !== null}
                    onClick={() => void runCli(c.id)}
                  >
                    <strong>{cliBusy === c.id ? (isZh ? "执行中..." : "Running...") : c.label}</strong>
                    <span className="mono small muted ellipsis">{c.cmd}</span>
                  </button>
                ))}
              </div>
              {cliOutput && (
                <div style={{ marginTop: 10 }}>
                  <div className="row" style={{ gap: 10, marginBottom: 6 }}>
                    <span className={`donut-pill ${cliOutput.exitCode === 0 ? "donut-pill-success" : "donut-pill-failed"}`}>
                      <span className="donut-dot" />
                      exit {cliOutput.exitCode} · {cliOutput.durationMs} ms
                    </span>
                    <code className="mono small muted">{cliOutput.cmd}</code>
                  </div>
                  <pre className="donut-console" style={{ margin: 0, maxHeight: 260 }}>
                    {[cliOutput.stdout, cliOutput.stderr].filter(Boolean).join("\n\n--- stderr ---\n") || "(empty output)"}
                  </pre>
                </div>
              )}
            </div>
          )}

          {info && (
            <div style={{ marginTop: 16 }}>
              <div className="api-sub-title">{isZh ? "Local API v1 端点清单" : "Local API v1 Endpoints"}</div>
              <div className="donut-table-box" style={{ marginTop: 6, maxHeight: 260 }}>
                <table className="grid">
                  <thead>
                    <tr>
                      <th>Method</th>
                      <th>Endpoint</th>
                      <th>{isZh ? "说明" : "Description"}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {info.endpoints.map((ep) => (
                      <tr key={`${ep.method}-${ep.path}`}>
                        <td>
                          <span className={`api-method api-method-${ep.method.toLowerCase()}`}>
                            {ep.method}
                          </span>
                        </td>
                        <td className="mono small">{ep.path}</td>
                        <td className="small muted">{ep.desc}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>

        {/* Section 3: External Service API Keys (.env 0600) */}
        <div className="donut-panel">
          <div className="donut-panel-head" style={{ flexWrap: "wrap", gap: 10 }}>
            <div>
              <h3>{isZh ? "外部服务 API Keys（写入状态目录 .env · 0600 权限）" : "External Service API Keys (.env 0600)"}</h3>
              <p className="muted small mono" style={{ margin: "2px 0 0" }}>
                {keys?.path}
              </p>
            </div>
            <div className="row" style={{ gap: 8 }}>
              {keysSaved && (
                <span className="donut-pill donut-pill-success">
                  <span className="donut-dot" />
                  {isZh ? "已加密落盘 (.env)" : "Saved (.env)"}
                </span>
              )}
              <button className="primary" disabled={keysBusy} onClick={() => void saveSecretKeys()}>
                {keysBusy ? (isZh ? "保存中..." : "Saving...") : (isZh ? "保存服务 Keys" : "Save Keys")}
              </button>
            </div>
          </div>

          {keys && (
            <div className="api-secrets-grid">
              {keys.items.map((item) => {
                const shown = !item.secret || revealedKeys.has(item.key);
                return (
                  <div key={item.key} className="api-secret-card">
                    <div className="api-secret-head">
                      <div>
                        <span className="donut-os-badge" style={{ marginRight: 6 }}>{item.group}</span>
                        <strong className="small">{item.label}</strong>
                      </div>
                      <span className={`donut-pill ${item.configured ? "donut-pill-success" : "donut-pill-manual"}`}>
                        <span className="donut-dot" />
                        {item.configured ? (isZh ? "已配置" : "Set") : (isZh ? "未配置" : "Unset")}
                      </span>
                    </div>
                    <div className="mono small muted" style={{ margin: "4px 0 6px" }}>{item.key}</div>
                    <div className="row" style={{ gap: 6 }}>
                      <input
                        style={{ flex: 1 }}
                        type={shown ? "text" : "password"}
                        autoComplete="off"
                        spellCheck={false}
                        placeholder={item.placeholder}
                        value={keyDraft[item.key] ?? ""}
                        onChange={(e) =>
                          setKeyDraft((cur) => ({ ...cur, [item.key]: e.target.value }))
                        }
                      />
                      {item.secret && (
                        <button
                          type="button"
                          className="ghost"
                          onClick={() =>
                            setRevealedKeys((prev) => {
                              const next = new Set(prev);
                              if (next.has(item.key)) next.delete(item.key);
                              else next.add(item.key);
                              return next;
                            })
                          }
                        >
                          {shown ? (isZh ? "隐藏" : "Hide") : (isZh ? "显示" : "Show")}
                        </button>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
