// SPDX-License-Identifier: AGPL-3.0-or-later
// Batch Account + Password + 2FA (+ optional Proxy) importer modal for Camoufox Studio.

import { useEffect, useMemo, useState } from "react";
import { api, type LocalProxy, type Project } from "../api";
import { isLikelyTotpSecret, parseAccountBatch } from "../totp";
import { Select } from "./Select";

export function AccountImportModal({
  isZh,
  projectId,
  localProjects,
  onClose,
  onDone,
}: {
  isZh: boolean;
  projectId: string | null;
  localProjects: Project[];
  onClose: () => void;
  onDone: (summary: string) => void;
}) {
  const [text, setText] = useState("");
  const [targetProject, setTargetProject] = useState(projectId ?? "");
  const [newProjectName, setNewProjectName] = useState("");
  const [defaultProxyId, setDefaultProxyId] = useState("");
  const [startUrl, setStartUrl] = useState("https://accounts.google.com");
  const [autoGeo, setAutoGeo] = useState(true);
  const [proxies, setProxies] = useState<LocalProxy[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    void api.proxies("local").then(setProxies).catch(() => setProxies([]));
  }, []);

  const parsed = useMemo(() => parseAccountBatch(text), [text]);

  const runImport = async () => {
    if (parsed.length === 0) return;
    setBusy(true);
    setError(null);
    try {
      const res = await api.importAccountsBatch({
        items: parsed.map((row) => ({
          email: row.email,
          password: row.password,
          totp: row.totp,
          proxyLine: row.proxyLine || undefined,
        })),
        projectId: targetProject && targetProject !== "__new__" ? targetProject : null,
        projectNameNew: targetProject === "__new__" ? newProjectName.trim() : undefined,
        defaultProxyId: defaultProxyId || null,
        startUrls: startUrl
          .split(/\r?\n/)
          .map((s) => s.trim())
          .filter(Boolean),
        autoGeo,
      });
      const okCount = res.created.length;
      const failCount = res.failed.length;
      const msg = isZh
        ? `已导入 ${okCount} 个账号环境${failCount > 0 ? `（失败 ${failCount} 个）` : ""}，含自动 2FA 与浏览器快捷输入悬浮条`
        : `Imported ${okCount} account profile(s)${failCount > 0 ? ` (${failCount} failed)` : ""}`;
      onDone(msg);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="scrim" onMouseDown={(e) => e.target === e.currentTarget && !busy && onClose()}>
      <div className="modal" role="dialog" aria-modal="true" style={{ maxWidth: 820 }}>
        <div className="modalHead">
          <h2>{isZh ? "批量导入账号（账号 + 密码 + 2FA）" : "Batch Import Accounts (Email + Password + 2FA)"}</h2>
        </div>

        <div className="modalBody" style={{ display: "grid", gap: 14, padding: "16px 20px" }}>
          <div>
            <label style={{ display: "block", marginBottom: 6, fontWeight: 600 }}>
              {isZh ? "每行一条，支持空格 / Tab / ---- / | / 逗号分隔，可附带代理（ip:port:user:pass）" : "One account per line (space, tab, ----, |, or comma separated; optional proxy)"}
            </label>
            <textarea
              rows={6}
              value={text}
              onChange={(e) => setText(e.target.value)}
              placeholder={
                "alice@example.com MyPass123456 JBSWY3DPEHPK3PXP\n" +
                "203.0.113.10:1080:proxyuser:proxypass bob@example.com Pass987654 JBSWY3DPEHPK3PXP\n" +
                "charlie@example.com----Pass123----JBSWY3DPEHPK3PXP"
              }
              style={{ width: "100%", fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace", fontSize: 12 }}
            />
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
            <div>
              <label style={{ display: "block", marginBottom: 4, fontSize: 12 }} className="muted">
                {isZh ? "归属项目分组" : "Project folder"}
              </label>
              <Select value={targetProject} onChange={(e) => setTargetProject(e.target.value)}>
                <option value="">{isZh ? "未分组" : "No project"}</option>
                {localProjects.map((p) => (
                  <option key={p.id} value={p.id}>{p.name}</option>
                ))}
                <option value="__new__">{isZh ? "＋ 新建项目分组..." : "+ New project..."}</option>
              </Select>
              {targetProject === "__new__" && (
                <input
                  style={{ marginTop: 6, width: "100%" }}
                  value={newProjectName}
                  placeholder={isZh ? "输入新项目名，如：US Gmail" : "New project name"}
                  onChange={(e) => setNewProjectName(e.target.value)}
                />
              )}
            </div>

            <div>
              <label style={{ display: "block", marginBottom: 4, fontSize: 12 }} className="muted">
                {isZh ? "默认代理（行内未带代理时使用）" : "Fallback proxy (if line has no proxy)"}
              </label>
              <Select value={defaultProxyId} onChange={(e) => setDefaultProxyId(e.target.value)}>
                <option value="">{isZh ? "不统一绑定（按行内代理或稍后分配）" : "None (use per-line proxy or assign later)"}</option>
                {proxies.map((px) => (
                  <option key={px.id} value={px.id}>
                    {px.last_country ? `[${px.last_country}] ` : ""}{px.name || `${px.host}:${px.port}`}
                  </option>
                ))}
              </Select>
            </div>
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "1fr auto", gap: 12, alignItems: "end" }}>
            <div>
              <label style={{ display: "block", marginBottom: 4, fontSize: 12 }} className="muted">
                {isZh ? "打开浏览器后默认打开网址" : "Default start URL"}
              </label>
              <input
                value={startUrl}
                onChange={(e) => setStartUrl(e.target.value)}
                style={{ width: "100%" }}
              />
            </div>
            <label className="row" style={{ gap: 6, paddingBottom: 6, whiteSpace: "nowrap" }}>
              <input
                type="checkbox"
                checked={autoGeo}
                onChange={(e) => setAutoGeo(e.target.checked)}
                style={{ width: 14, height: 14, accentColor: "var(--accent)" }}
              />
              <span className="small">{isZh ? "自动按代理 IP 匹配时区与语言" : "Auto-match timezone & language to proxy IP"}</span>
            </label>
          </div>

          {parsed.length > 0 && (
            <div className="acctImportPreview">
              <div className="muted small" style={{ marginBottom: 6 }}>
                {isZh ? `已识别 ${parsed.length} 条记录：` : `Recognized ${parsed.length} account(s):`}
              </div>
              <div style={{ maxHeight: 190, overflowY: "auto", border: "1px solid var(--line)", borderRadius: 8 }}>
                <table className="grid" style={{ fontSize: 12 }}>
                  <thead>
                    <tr>
                      <th style={{ width: 34 }}>#</th>
                      <th>{isZh ? "账号 / 邮箱" : "Email / Account"}</th>
                      <th>{isZh ? "密码" : "Password"}</th>
                      <th>2FA</th>
                      <th>{isZh ? "行内代理" : "Inline Proxy"}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {parsed.map((row, idx) => (
                      <tr key={idx}>
                        <td className="muted">{idx + 1}</td>
                        <td className="mono">{row.email || "—"}</td>
                        <td className="mono muted">{row.password ? "••••••••" : "—"}</td>
                        <td>
                          {row.totp ? (
                            <span className={isLikelyTotpSecret(row.totp) ? "totpBadgeOk" : "muted small"}>
                              {isLikelyTotpSecret(row.totp) ? (isZh ? "✓ 有效 TOTP" : "✓ TOTP") : row.totp.slice(0, 10)}
                            </span>
                          ) : (
                            <span className="dim">—</span>
                          )}
                        </td>
                        <td className="mono muted">{row.proxyLine ? row.proxyLine.split(":").slice(0, 2).join(":") : "—"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {error && <p className="error">{error}</p>}
        </div>

        <div className="modalFoot">
          <button className="ghost" disabled={busy} onClick={onClose}>
            {isZh ? "取消" : "Cancel"}
          </button>
          <button
            className="primary"
            disabled={busy || parsed.length === 0 || (targetProject === "__new__" && !newProjectName.trim())}
            onClick={() => void runImport()}
          >
            {busy
              ? (isZh ? "导入并检测代理地理中..." : "Importing...")
              : (isZh ? `导入 ${parsed.length} 个账号环境` : `Import ${parsed.length} Account(s)`)}
          </button>
        </div>
      </div>
    </div>
  );
}
