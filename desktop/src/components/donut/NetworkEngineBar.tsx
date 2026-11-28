// SPDX-License-Identifier: AGPL-3.0-or-later
// xfrpc-ios (NexusEdge netd) Network Engine Control Panel
// Exposes Proxy engine selection, DoT DNS disguise, UDP / TCP<->UDP (0xF1/0xF2) controls, and live active relay ports.

import { useCallback, useEffect, useState } from "react";
import { api, type SuiteNetworkConfig, type SuiteNetworkStatus } from "../../api";
import { Select } from "../Select";

export function NetworkEngineBar({ isZh }: { isZh: boolean }) {
  const [status, setStatus] = useState<SuiteNetworkStatus | null>(null);
  const [draft, setDraft] = useState<SuiteNetworkConfig | null>(null);
  const [saving, setSaving] = useState(false);
  const [savedToast, setSavedToast] = useState(false);
  const [expanded, setExpanded] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      const res = await api.suiteNetworkStatus();
      setStatus(res);
      setDraft((prev) => prev ?? res.defaults);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }, []);

  useEffect(() => {
    void refresh();
    const timer = window.setInterval(() => void refresh(), 5000);
    return () => window.clearInterval(timer);
  }, [refresh]);

  const saveConfig = async (next: SuiteNetworkConfig) => {
    setDraft(next);
    setSaving(true);
    setError(null);
    try {
      const res = await api.suiteSaveNetworkDefaults(next);
      setDraft(res.defaults);
      setStatus((prev) => (prev ? { ...prev, defaults: res.defaults } : prev));
      setSavedToast(true);
      window.setTimeout(() => setSavedToast(false), 1800);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setSaving(false);
    }
  };

  if (!status || !draft) return null;

  const netdReady = status.netd.available;
  const activeCount = status.active_relays.length;

  return (
    <section className="netdCard">
      <div className="netdHead">
        <div className="netdTitleGroup">
          <span className={`netdDot ${netdReady ? "ok" : "warn"}`} />
          <div>
            <div className="netdTitleRow">
              <strong>
                {isZh ? "xfrpc-ios (netd) 代理 · DNS 伪装 · TCP↔UDP 引擎" : "xfrpc-ios (netd) Proxy · DNS Disguise · TCP↔UDP"}
              </strong>
              <span className="netdPill ok">
                {netdReady ? (isZh ? "原生 C23 netd 就绪" : "Native netd Ready") : (isZh ? "Node 中继模式" : "Node Relay")}
              </span>
              <span className="netdPill accent">SOCKS5 TCP+UDP</span>
              <span className="netdPill blue">DoT RFC 7858</span>
              {draft.tcp2udp_enable && <span className="netdPill purple">0xF1/0xF2 TCP↔UDP</span>}
              {activeCount > 0 && (
                <span className="netdPill">
                  {isZh ? `${activeCount} 个活动隧道` : `${activeCount} active`}
                </span>
              )}
            </div>
            <div className="muted small">
              {isZh
                ? "每个环境启动时自动拉起独立回环混合代理、DoT 加密防泄漏 DNS 存根与 SOCKS5 UDP / 0xF1 TCP→UDP 转换桥（免认证弹窗）。"
                : "Spawns an isolated loopback mixed proxy, fail-closed DoT DNS stub, and SOCKS5 UDP / 0xF1 TCP→UDP bridge per launched profile."}
            </div>
          </div>
        </div>
        <div className="netdHeadActions">
          {savedToast && <span className="netdSaved">{isZh ? "已保存（下次打开环境生效）" : "Saved"}</span>}
          <button type="button" className="ghost" onClick={() => setExpanded((v) => !v)}>
            {expanded ? (isZh ? "收起配置" : "Collapse") : (isZh ? "展开配置" : "Configure")}
          </button>
        </div>
      </div>

      {error && <div className="warn small" style={{ marginTop: 8 }}>{error}</div>}

      {expanded && (
        <>
          <div className="netdGrid">
            <label className="netdField">
              <span>{isZh ? "代理核心引擎" : "Proxy Engine"}</span>
              <Select
                value={draft.engine}
                disabled={saving}
                onChange={(e) => void saveConfig({ ...draft, engine: e.target.value as SuiteNetworkConfig["engine"] })}
              >
                <option value="xfrpc-netd" disabled={!netdReady}>
                  {isZh ? "xfrpc-ios 原生 netd（推荐 · 4 插件全开）" : "xfrpc-ios native netd (Recommended)"}
                </option>
                <option value="node-relay">
                  {isZh ? "纯 Node.js SOCKS5/HTTP 中继" : "Pure Node.js SOCKS5/HTTP Relay"}
                </option>
              </Select>
            </label>

            <label className="netdField">
              <span>{isZh ? "DNS 伪装策略 (DoT Fail-Closed)" : "DNS Disguise (DoT)"}</span>
              <Select
                value={draft.dns_disguise}
                disabled={saving}
                onChange={(e) => void saveConfig({ ...draft, dns_disguise: e.target.value })}
              >
                {status.dns_presets.map((p) => (
                  <option key={p.id} value={p.id}>
                    {p.label}
                  </option>
                ))}
              </Select>
            </label>

            <label className="netdField">
              <span>{isZh ? "UDP 代理 / WebRTC 模式" : "UDP / WebRTC Mode"}</span>
              <Select
                value={draft.udp_mode}
                disabled={saving}
                onChange={(e) => void saveConfig({ ...draft, udp_mode: e.target.value as SuiteNetworkConfig["udp_mode"] })}
              >
                <option value="socks5-udp">
                  {isZh ? "SOCKS5 UDP ASSOCIATE + WebRTC 中继防泄漏" : "SOCKS5 UDP ASSOCIATE + WebRTC Guard"}
                </option>
                <option value="udp-over-tcp">
                  {isZh ? "UDP-over-TCP (0xF1/0xF2 TCP↔UDP 隧道)" : "UDP-over-TCP (0xF1/0xF2)"}
                </option>
                <option value="block-udp">
                  {isZh ? "严格阻断直连 UDP（仅 TCP/Relay）" : "Block Direct UDP (TCP/Relay Only)"}
                </option>
              </Select>
            </label>

            <label className="netdField">
              <span>{isZh ? "出口协议族 (Egress)" : "Egress Family"}</span>
              <Select
                value={draft.egress}
                disabled={saving}
                onChange={(e) => void saveConfig({ ...draft, egress: e.target.value as SuiteNetworkConfig["egress"] })}
              >
                <option value="prefer_v4">{isZh ? "优先 IPv4 (prefer_v4)" : "Prefer IPv4"}</option>
                <option value="v4">{isZh ? "严格 IPv4 (v4)" : "Strict IPv4"}</option>
                <option value="prefer_v6">{isZh ? "优先 IPv6 (prefer_v6)" : "Prefer IPv6"}</option>
                <option value="v6">{isZh ? "严格 IPv6 (v6)" : "Strict IPv6"}</option>
              </Select>
            </label>
          </div>

          <div className="netdSubRow">
            <label className="row" style={{ gap: 8 }}>
              <input
                type="checkbox"
                style={{ width: 14, height: 14, accentColor: "var(--accent)" }}
                checked={draft.tcp2udp_enable}
                disabled={saving}
                onChange={(e) => void saveConfig({ ...draft, tcp2udp_enable: e.target.checked })}
              />
              <span className="small">
                {isZh
                  ? "启用每环境独立 TCP↔UDP 转换端口（兼容 xfrpc-ios 0xF1 UDP_CONN / 0xF2 UDP_MUX 帧协议）"
                  : "Enable per-profile TCP↔UDP converter port (xfrpc-ios 0xF1/0xF2 framing)"}
              </span>
            </label>

            <div className="netdSplitInput">
              <input
                value={draft.dns_split_rules}
                placeholder={isZh ? "可选 Split-DNS 分流规则，如 *.jp->1.1.1.1:853#cloudflare-dns.com" : "Optional split_dns rules"}
                onChange={(e) => setDraft({ ...draft, dns_split_rules: e.target.value })}
                onBlur={() => {
                  if (draft.dns_split_rules !== status.defaults.dns_split_rules) {
                    void saveConfig(draft);
                  }
                }}
              />
            </div>
          </div>

          {status.active_relays.length > 0 && (
            <div className="netdActiveList">
              {status.active_relays.map((r) => (
                <div key={r.profile_id} className="netdRelayItem">
                  <strong>{r.profile_name}</strong>
                  <span className="mono small">SOCKS5/HTTP 127.0.0.1:{r.proxy_port}</span>
                  {r.dns_stub_port && <span className="mono small">DoT DNS 127.0.0.1:{r.dns_stub_port}</span>}
                  {r.tcp2udp_port && <span className="mono small">TCP↔UDP 127.0.0.1:{r.tcp2udp_port}</span>}
                  <span className="muted small">{r.engine} · {r.upstream_mode}</span>
                </div>
              ))}
            </div>
          )}
        </>
      )}
    </section>
  );
}
