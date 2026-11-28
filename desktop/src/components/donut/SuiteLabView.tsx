// SPDX-License-Identifier: AGPL-3.0-or-later
// Full-spectrum Live Camoufox C++ Coherence Auditor (17 Runtime + 4 Pre-TLS Wire Checks)
// and Cryptographic Pre-TLS Recording & Wire-Dump Replay Auditor UI.

import { useCallback, useEffect, useMemo, useState } from "react";
import {
  api,
  type Profile,
  type SuiteAdsPowerAudit,
  type SuiteCoherenceCheckItem,
  type SuiteCoherenceRun,
  type SuiteEnvConfig,
  type SuiteMeasuredTelemetry,
  type SuiteOverview,
  type SuitePreset,
  type SuiteResultsHistory,
  type SuiteSingleProfileAudit,
  type SuiteTrafficProfileItem,
  type SuiteTrafficQueryResult,
  type SuiteTrafficSummary,
  type SuiteTrafficWireDumpResult,
} from "../../api";
import { BandwidthSparkline } from "./BandwidthSparkline";
import { ProfileHandoffStatus } from "./ProfileHandoffStatus";

export type LabTab = "coherence" | "traffic" | "adspower" | "config";
type ReplaySubTab = "transactions" | "signatures" | "cookies" | "anomalies";

function formatBytes(bytes: number): string {
  if (!bytes || bytes < 1024) return `${bytes || 0} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

function ScoreRing({ score, passed }: { score: number; passed: boolean }) {
  const r = 17;
  const c = 2 * Math.PI * r;
  const pct = Math.max(0, Math.min(100, score));
  const offset = c * (1 - pct / 100);
  return (
    <div className="donut-ring-wrap" aria-hidden="true">
      <svg width="44" height="44" viewBox="0 0 44 44">
        <circle cx="22" cy="22" r={r} fill="none" stroke="var(--line-strong)" strokeWidth="3.2" />
        <circle
          cx="22"
          cy="22"
          r={r}
          fill="none"
          stroke={passed ? "var(--ok)" : "var(--accent)"}
          strokeWidth="3.2"
          strokeLinecap="round"
          strokeDasharray={c}
          strokeDashoffset={offset}
          transform="rotate(-90 22 22)"
        />
      </svg>
      <span className="donut-ring-num">{pct}</span>
    </div>
  );
}

function TelemetryGrid({ measured, isZh }: { measured: SuiteMeasuredTelemetry | null | undefined; isZh: boolean }) {
  if (!measured) return null;
  const items = [
    { k: "User-Agent", v: measured.userAgent || "—" },
    { k: isZh ? "平台 / OSCPU" : "Platform / OSCPU", v: `${measured.platform || "—"} · ${measured.oscpu || "—"}` },
    { k: isZh ? "CPU 逻辑核心" : "CPU Cores", v: `${measured.hardwareConcurrency ?? "—"} Cores` },
    { k: "WebGL Vendor", v: measured.webglVendor || "—" },
    { k: "WebGL Renderer", v: measured.webglRenderer || "—" },
    {
      k: isZh ? "WebGL 版本 / 扩展 / WebGPU" : "WebGL / Ext / WebGPU",
      v: `${measured.webglVersion || "—"} · ext=${measured.webglExtensionsCount ?? 0} · WebGPU=${String(measured.webgpuAvailable)}`,
    },
    { k: "Canvas 2D FNV-1a", v: measured.canvasHash || "—" },
    { k: "IEEE-754 sin(1e6) / cos(1e6)", v: `${measured.mathSinHex || "—"} / ${measured.mathCosHex || "—"}` },
    { k: isZh ? "屏幕与色深" : "Screen & Depth", v: measured.screen || "—" },
    { k: isZh ? "Intl 时区 / 语言" : "Timezone / Locale", v: `${measured.timeZone || "—"} · ${measured.language || "—"} [${(measured.languages || []).join(", ")}]` },
    {
      k: isZh ? "AudioContext / Speech 语音" : "Audio / Speech Voices",
      v: `${measured.audioSampleRate ?? "—"}Hz (${measured.audioChannels ?? "—"}ch) · voices=${measured.voicesCount}`,
    },
    {
      k: isZh ? "探针检出字体" : "Detected OS Fonts",
      v: measured.detectedFonts?.length ? measured.detectedFonts.join(", ") : "—",
    },
    {
      k: isZh ? "跨线程 / iframe / 原型链" : "Worker / iframe / Prototype",
      v: `Worker=${measured.workerParityOk ? "PASS" : "FAIL"} · iframe=${measured.iframeParityOk ? "PASS" : "FAIL"} · [native code]=${measured.toStringIntact ? "PASS" : "FAIL"} · webdriver=${String(measured.webdriver)}`,
    },
  ];
  return (
    <div className="donut-telemetry-kv-grid">
      {items.map((it) => (
        <div key={it.k} className="donut-telemetry-kv">
          <span className="muted small">{it.k}</span>
          <span className="mono small ellipsis" title={it.v}>{it.v}</span>
        </div>
      ))}
    </div>
  );
}

function ChecksList({ checks, isZh }: { checks: SuiteCoherenceCheckItem[]; isZh: boolean }) {
  if (!checks.length) return null;
  return (
    <div className="donut-checks-list">
      {checks.map((chk, idx) => {
        const passed = Boolean(chk.passed) && chk.status !== "not-tested";
        const detail = chk.details || chk.detail || "";
        const isWire = chk.category === "pre-tls-wire" || chk.name.startsWith("wire-");
        return (
          <div key={`${chk.name}-${idx}`} className={`donut-check-item ${passed ? "ok" : "fail"}`}>
            <div className="row" style={{ justifyContent: "space-between", gap: 6 }}>
              <strong className="mono small ellipsis" title={chk.name}>
                {passed ? "✓" : "✗"} {chk.name}
              </strong>
              <span className={`donut-pill ${passed ? "donut-pill-success" : "donut-pill-failed"}`}>
                {isWire ? (isZh ? "Pre-TLS Wire" : "Wire") : "DOM"} · {passed ? "PASS" : (chk.status || "FAIL").toUpperCase()}
              </span>
            </div>
            {detail && (
              <div className="muted small" style={{ wordBreak: "break-word" }}>
                {detail}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

export function SuiteLabView({
  isZh,
  initialTab = "coherence",
  onProfilesChanged,
  onCreateFromPreset,
}: {
  isZh: boolean;
  initialTab?: LabTab;
  onProfilesChanged: () => void;
  onCreateFromPreset: (preset: SuitePreset) => void;
}) {
  const [tab, setTab] = useState<LabTab>(initialTab);
  useEffect(() => {
    setTab(initialTab);
  }, [initialTab]);

  const [overview, setOverview] = useState<SuiteOverview | null>(null);
  const [savedProfiles, setSavedProfiles] = useState<Profile[]>([]);
  const [presets, setPresets] = useState<SuitePreset[]>([]);
  const [osFilter, setOsFilter] = useState<"all" | "macos" | "windows" | "linux">("all");
  const [presetQuery, setPresetQuery] = useState("");

  const [coherence, setCoherence] = useState<SuiteCoherenceRun | null>(null);
  const [auditBusy, setAuditBusy] = useState(false);
  const [baselineBusy, setBaselineBusy] = useState(false);
  const [expandedOsKey, setExpandedOsKey] = useState<string | null>(null);

  // Single profile live + recorded audit state
  const [selectedAuditProfileId, setSelectedAuditProfileId] = useState<string>("");
  const [auditTargetUrl, setAuditTargetUrl] = useState<string>("");
  const [singleAuditBusy, setSingleAuditBusy] = useState(false);
  const [singleAuditResult, setSingleAuditResult] = useState<SuiteSingleProfileAudit | null>(null);

  // Pre-TLS Recording & Replay Auditor state
  const [traffic, setTraffic] = useState<SuiteTrafficSummary | null>(null);
  const [trafficProfiles, setTrafficProfiles] = useState<SuiteTrafficProfileItem[]>([]);
  const [selectedReplayProfileId, setSelectedReplayProfileId] = useState<string>("");
  const [replaySubTab, setReplaySubTab] = useState<ReplaySubTab>("transactions");
  const [filterDomain, setFilterDomain] = useState("");
  const [filterStatus, setFilterStatus] = useState("");
  const [filterPlatform, setFilterPlatform] = useState("");
  const [filterStep, setFilterStep] = useState("");
  const [trafficDetail, setTrafficDetail] = useState<SuiteTrafficQueryResult | null>(null);
  const [trafficBusy, setTrafficBusy] = useState(false);
  const [wireDumpBusy, setWireDumpBusy] = useState(false);
  const [activeWireDump, setActiveWireDump] = useState<SuiteTrafficWireDumpResult | null>(null);
  const [harNotice, setHarNotice] = useState<string | null>(null);

  const [adsCacheDir, setAdsCacheDir] = useState("");
  const [adsAudit, setAdsAudit] = useState<SuiteAdsPowerAudit | null>(null);
  const [adsBusy, setAdsBusy] = useState(false);
  const [adsMessage, setAdsMessage] = useState<string | null>(null);

  const [history, setHistory] = useState<SuiteResultsHistory | null>(null);
  const [envCfg, setEnvCfg] = useState<SuiteEnvConfig | null>(null);
  const [envDraft, setEnvDraft] = useState<Record<string, string>>({});
  const [envSaved, setEnvSaved] = useState(false);

  const [error, setError] = useState<string | null>(null);

  const loadAll = useCallback(async () => {
    setError(null);
    try {
      const [ov, profs, ps, tr, trProfs, hist, env] = await Promise.all([
        api.suiteOverview(),
        api.profiles(),
        api.suitePresets(),
        api.suiteTrafficSummary(),
        api.suiteTrafficProfiles().catch(() => []),
        api.suiteResultsHistory(),
        api.suiteGetEnv(),
      ]);
      setOverview(ov);
      setSavedProfiles(profs);
      if (profs.length > 0) {
        setSelectedAuditProfileId((cur) => cur || profs[0].id);
      }
      setPresets(ps);
      setCoherence(ov.lastCoherence);
      setTraffic(tr);
      setTrafficProfiles(trProfs);
      if (trProfs.length > 0) {
        setSelectedReplayProfileId((cur) => cur || trProfs[0].profileId);
      }
      setHistory(hist);
      setEnvCfg(env);
      setEnvDraft({ ...env.values });
    } catch (e: any) {
      setError(e?.message || String(e));
    }
  }, []);

  useEffect(() => {
    void loadAll();
  }, [loadAll]);

  const loadReplayQuery = useCallback(
    async (profileId: string) => {
      if (!profileId) {
        setTrafficDetail(null);
        return;
      }
      setTrafficBusy(true);
      setError(null);
      try {
        const res = await api.suiteTrafficQuery({
          profileId,
          domain: filterDomain.trim() || undefined,
          status: filterStatus.trim() || undefined,
          platform: filterPlatform.trim() || undefined,
          step: filterStep.trim() || undefined,
        });
        setTrafficDetail(res);
      } catch (e: any) {
        setError(e?.message || String(e));
      } finally {
        setTrafficBusy(false);
      }
    },
    [filterDomain, filterStatus, filterPlatform, filterStep],
  );

  useEffect(() => {
    if (tab === "traffic" && selectedReplayProfileId) {
      void loadReplayQuery(selectedReplayProfileId);
    }
  }, [tab, selectedReplayProfileId, loadReplayQuery]);

  const filteredPresets = useMemo(() => {
    const q = presetQuery.trim().toLowerCase();
    return presets.filter((p) => {
      if (osFilter !== "all" && p.os !== osFilter) return false;
      if (!q) return true;
      return [p.presetId, p.deviceModel, p.cpuModel, p.gpuModel, p.webgl.unmaskedRenderer]
        .join(" ")
        .toLowerCase()
        .includes(q);
    });
  }, [presets, osFilter, presetQuery]);

  const ensureBaselineNow = async () => {
    setBaselineBusy(true);
    setError(null);
    try {
      await api.suiteEnsureBaseline();
      setOverview(await api.suiteOverview());
    } catch (e: any) {
      setError(e?.message || String(e));
    } finally {
      setBaselineBusy(false);
    }
  };

  const runCoherence = async (dryRun = false) => {
    setAuditBusy(true);
    setError(null);
    try {
      const res = await api.suiteRunCoherence(dryRun);
      setCoherence(res);
      setOverview(await api.suiteOverview());
      const firstOs = Array.isArray(res.report?.results) ? res.report?.results[0]?.targetOs : "macos";
      if (firstOs) setExpandedOsKey(firstOs);
    } catch (e: any) {
      setError(e?.message || String(e));
    } finally {
      setAuditBusy(false);
    }
  };

  const runSingleProfileAudit = async () => {
    if (!selectedAuditProfileId) return;
    setSingleAuditBusy(true);
    setError(null);
    try {
      const res = await api.suiteAuditProfile(selectedAuditProfileId, auditTargetUrl.trim() || undefined);
      setSingleAuditResult(res);
      const [ov, tr, trProfs] = await Promise.all([
        api.suiteOverview(),
        api.suiteTrafficSummary(),
        api.suiteTrafficProfiles().catch(() => []),
      ]);
      setOverview(ov);
      setTraffic(tr);
      setTrafficProfiles(trProfs);
      setSelectedReplayProfileId(res.profileId);
    } catch (e: any) {
      setError(e?.message || String(e));
    } finally {
      setSingleAuditBusy(false);
    }
  };

  const refreshTraffic = async () => {
    setTrafficBusy(true);
    setError(null);
    try {
      const [tr, trProfs] = await Promise.all([
        api.suiteTrafficSummary(),
        api.suiteTrafficProfiles().catch(() => []),
      ]);
      setTraffic(tr);
      setTrafficProfiles(trProfs);
      const targetId = selectedReplayProfileId || trProfs[0]?.profileId || "";
      if (targetId) {
        if (!selectedReplayProfileId) setSelectedReplayProfileId(targetId);
        await loadReplayQuery(targetId);
      }
    } finally {
      setTrafficBusy(false);
    }
  };

  const openWireReplay = async (profileId: string, correlationId: string) => {
    if (!profileId || !correlationId) return;
    setWireDumpBusy(true);
    setError(null);
    try {
      const dump = await api.suiteTrafficWireDump(profileId, correlationId);
      setActiveWireDump(dump);
    } catch (e: any) {
      setError(e?.message || String(e));
    } finally {
      setWireDumpBusy(false);
    }
  };

  const exportHarNow = async () => {
    if (!selectedReplayProfileId) return;
    setError(null);
    setHarNotice(null);
    try {
      const res = await api.suiteTrafficExportHar(
        selectedReplayProfileId,
        filterDomain.trim() || undefined,
        filterStatus.trim() || undefined,
      );
      setHarNotice(
        isZh
          ? `已导出 W3C HAR 1.2 (${res.entryCount ?? 0} 条事务, ${formatBytes(res.bytes ?? 0)}) → ${res.harPath || "traffic/"}`
          : `Exported HAR 1.2 (${res.entryCount ?? 0} entries) -> ${res.harPath || "traffic/"}`,
      );
    } catch (e: any) {
      setError(e?.message || String(e));
    }
  };

  const launchProfileForRecording = async (profileId: string) => {
    if (!profileId) return;
    setError(null);
    try {
      await api.launch(profileId);
      onProfilesChanged();
      setTimeout(() => {
        void refreshTraffic();
      }, 1500);
    } catch (e: any) {
      setError(e?.message || String(e));
    }
  };

  const runAdsAudit = async () => {
    if (!adsCacheDir.trim()) return;
    setAdsBusy(true);
    setError(null);
    setAdsMessage(null);
    try {
      const res = await api.suiteAuditAdspower(adsCacheDir.trim());
      setAdsAudit(res);
    } catch (e: any) {
      setError(e?.message || String(e));
    } finally {
      setAdsBusy(false);
    }
  };

  const healAllAds = async () => {
    if (!adsCacheDir.trim()) return;
    setAdsBusy(true);
    setError(null);
    try {
      const res = await api.suiteHealAdspower(adsCacheDir.trim());
      setAdsMessage(
        isZh
          ? `已按 SKU 一致性预设自动修复并导入 ${res.imported.length} 个 Camoufox 环境。`
          : `Healed and imported ${res.imported.length} coherent Camoufox profiles.`,
      );
      onProfilesChanged();
    } catch (e: any) {
      setError(e?.message || String(e));
    } finally {
      setAdsBusy(false);
    }
  };

  const saveEnv = async () => {
    setError(null);
    setEnvSaved(false);
    try {
      const updated = await api.suiteSaveEnv(envDraft);
      setEnvCfg(updated);
      setEnvDraft({ ...updated.values });
      setEnvSaved(true);
      setTimeout(() => setEnvSaved(false), 2500);
    } catch (e: any) {
      setError(e?.message || String(e));
    }
  };

  const reportResults = useMemo(() => {
    const raw = coherence?.report?.results;
    if (!raw) return [];
    const list = Array.isArray(raw)
      ? raw
      : Object.entries(raw).map(([osKey, item]) => ({ ...item, targetOs: item.targetOs || osKey }));
    return list.map((item, idx) => {
      const checks = item.auditReport?.checks ?? item.checks ?? [];
      const key = item.targetOs || `os-${idx}`;
      const mode = item.mode || coherence?.mode || coherence?.report?.mode || "dry-run-synthetic";
      return {
        key,
        label: (item.targetOs || `OS ${idx + 1}`).toUpperCase(),
        presetId: item.presetId || null,
        deviceModel: item.deviceModel || null,
        passed: Boolean(item.passed),
        score: item.auditReport?.score ?? item.score ?? 0,
        mode,
        isLive: mode.startsWith("live-"),
        checksCount: checks.length,
        wireInspectedRequests: item.wireInspectedRequests ?? 0,
        measured: item.measured || null,
        checks,
      };
    });
  }, [coherence]);

  const expandedResult = useMemo(
    () => reportResults.find((r) => r.key === expandedOsKey) || reportResults[0] || null,
    [reportResults, expandedOsKey],
  );

  const negFlagged =
    coherence?.report?.negativeControl?.failedChecks ??
    coherence?.report?.negativeControl?.flaggedChecks ??
    [];
  const negPassed =
    coherence?.report?.negativeControl?.caughtAll ??
    coherence?.report?.negativeControl?.passed ??
    false;

  const isoProof = coherence?.report?.crossProfileIsolation ?? null;
  const isRealCamoufox = Boolean(overview?.isAntidetectEngine ?? (overview?.browserLauncher?.kind === "camoufox"));

  return (
    <div className="donut-lab">
      <div className="donut-lab-tabs" role="tablist">
        <button
          role="tab"
          aria-selected={tab === "coherence"}
          className={tab === "coherence" ? "donut-tab active" : "donut-tab"}
          onClick={() => setTab("coherence")}
        >
          {isZh
            ? `实机全量指纹审计 & ${presets.length || 37} SKU 预设`
            : `Live Fingerprint Audit & ${presets.length || 37} SKU Presets`}
        </button>
        <button
          role="tab"
          aria-selected={tab === "traffic"}
          className={tab === "traffic" ? "donut-tab active" : "donut-tab"}
          onClick={() => setTab("traffic")}
        >
          {isZh ? "Pre-TLS 录制回放审计" : "Pre-TLS Recording & Replay"}
        </button>
        <button
          role="tab"
          aria-selected={tab === "adspower"}
          className={tab === "adspower" ? "donut-tab active" : "donut-tab"}
          onClick={() => setTab("adspower")}
        >
          {isZh ? "AdsPower 缓存审计修复" : "AdsPower Healer"}
        </button>
        <button
          role="tab"
          aria-selected={tab === "config"}
          className={tab === "config" ? "donut-tab active" : "donut-tab"}
          onClick={() => setTab("config")}
        >
          {isZh ? "运行记录 & .env 配置" : "Handoffs & .env"}
        </button>
      </div>

      {overview && !isRealCamoufox && (
        <div className="notice warnBar" role="status" style={{ marginBottom: "var(--s-3)" }}>
          <span>
            {overview.baselineStatus === "installing"
              ? isZh
                ? "⏳ 正在后台自动下载安装仓库基线 Camoufox C++ 反检测内核（含多平台字体包、GeoIP 与 fpgen 模型），完成后将自动启用全维度硬件指纹隔离…"
                : "Auto-installing baseline Camoufox C++ browser engine in background..."
              : isZh
                ? `⚠️ 当前尚未检出 Camoufox C++ 内核${overview.baselineError ? ` (${overview.baselineError})` : ""}，切勿使用原版 Firefox 操作高风控账号。`
                : `Camoufox C++ engine is not installed yet${overview.baselineError ? ` (${overview.baselineError})` : ""}.`}
          </span>
          <button disabled={baselineBusy || overview.baselineStatus === "installing"} onClick={() => void ensureBaselineNow()}>
            {baselineBusy || overview.baselineStatus === "installing"
              ? isZh ? "安装中..." : "Installing..."
              : isZh ? "立即安装基线内核" : "Install Camoufox"}
          </button>
        </div>
      )}

      {error && (
        <div className="notice warnBar" role="alert" style={{ marginBottom: "var(--s-3)" }}>
          <span>{error}</span>
          <button className="linky" onClick={() => setError(null)}>×</button>
        </div>
      )}

      {tab === "coherence" && (
        <div className="donut-lab-body">
          {/* Panel 1: 21-Check Live 3-OS + Pre-TLS Wire + Cross-Profile Isolation Audit */}
          <div className="donut-panel">
            <div className="donut-panel-head" style={{ flexWrap: "wrap", gap: 10 }}>
              <div>
                <h3>
                  {isZh
                    ? "21 维实机内核 + Pre-TLS Wire 跨平台指纹一致性审计"
                    : "21-Check Live Browser + Pre-TLS Wire Coherence Audit"}
                </h3>
                <p className="muted small" style={{ margin: "2px 0 0" }}>
                  {isZh
                    ? "真实拉起 Camoufox C++ 内核采集 17 项运行时指纹（WebIDL 原型链、Blob Worker、动态 iframe、WebGL/WebGPU、Canvas FNV-1a、IEEE-754 浮点、AudioContext、语音、字体、SKU、GPU 算力缩放）+ 4 项 Pre-TLS Wire 报文交叉比对 + 多环境隔离证明。"
                    : "Boots real Camoufox C++ instances to verify 17 runtime DOM/Worker/iframe/WebGL/Canvas/Audio/Font/SKU vectors + 4 Pre-TLS wire header checks + cross-profile SKU isolation."}
                </p>
              </div>
              <div className="row" style={{ gap: 8 }}>
                <button disabled={auditBusy} onClick={() => void runCoherence(true)}>
                  {isZh ? "静态规则快检" : "Dry-Run Rules"}
                </button>
                <button className="primary" disabled={auditBusy} onClick={() => void runCoherence(false)}>
                  {auditBusy
                    ? isZh ? "正在实机启动三端审计..." : "Auditing Live..."
                    : isZh ? "运行实机全量审计 (21项×3端)" : "Run Live 21-Check Audit"}
                </button>
              </div>
            </div>

            {reportResults.length > 0 ? (
              <>
                <div className="donut-score-grid">
                  {reportResults.map((item) => {
                    const selected = expandedResult?.key === item.key;
                    return (
                      <div
                        key={item.key}
                        className={`donut-score-card donut-os-${item.key}`}
                        style={{
                          cursor: "pointer",
                          borderColor: selected ? "var(--accent)" : undefined,
                        }}
                        onClick={() => setExpandedOsKey(item.key)}
                      >
                        <div className="donut-score-row">
                          <ScoreRing score={item.score} passed={item.passed && item.isLive} />
                          <div style={{ flex: 1, minWidth: 0 }}>
                            <div className="donut-score-top">
                              <span className="donut-os-badge">{item.label}</span>
                              <span
                                className={`donut-pill ${
                                  !item.isLive
                                    ? "donut-pill-manual"
                                    : item.passed
                                      ? "donut-pill-success"
                                      : "donut-pill-failed"
                                }`}
                              >
                                <span className="donut-dot" />
                                {!item.isLive ? (isZh ? "模拟" : "DRY-RUN") : item.passed ? "LIVE PASS" : "FAIL"}
                              </span>
                            </div>
                            <div className="muted small ellipsis" style={{ marginTop: 5 }}>
                              {item.deviceModel || item.presetId || item.mode}
                            </div>
                            <div className="muted small mono" style={{ marginTop: 2 }}>
                              {isZh
                                ? `${item.checksCount} 项检查${item.wireInspectedRequests ? ` · Wire 报文=${item.wireInspectedRequests}` : ""} · 点击展开明细`
                                : `${item.checksCount} checks · click for details`}
                            </div>
                          </div>
                        </div>
                      </div>
                    );
                  })}
                </div>

                {isoProof && (
                  <div className="donut-neg-bar" style={{ marginTop: 10, flexWrap: "wrap", gap: 10 }}>
                    <span className={`donut-pill ${isoProof.passed ? "donut-pill-success" : "donut-pill-failed"}`}>
                      <span className="donut-dot" />
                      {isZh
                        ? `跨环境多 SKU 隔离证明: ${isoProof.passed ? "PASS" : "FAIL"}`
                        : `Cross-Profile SKU Isolation: ${isoProof.passed ? "PASS" : "FAIL"}`}
                    </span>
                    <span className="muted small mono">
                      A[{isoProof.profileA.presetId}: {isoProof.profileA.cores}T · {isoProof.profileA.gpu} · Canvas={isoProof.profileA.canvasHash} · {isoProof.profileA.timeZone}]
                      {" ≠ "}
                      B[{isoProof.profileB.presetId}: {isoProof.profileB.cores}T · {isoProof.profileB.gpu} · Canvas={isoProof.profileB.canvasHash} · {isoProof.profileB.timeZone}]
                    </span>
                  </div>
                )}

                {coherence?.report?.negativeControl && (
                  <div className="donut-neg-bar" style={{ marginTop: 8 }}>
                    <span className={`donut-pill ${negPassed ? "donut-pill-success" : "donut-pill-failed"}`}>
                      <span className="donut-dot" />
                      {isZh
                        ? `对抗篡改负例拦截: ${negPassed ? "PASS" : "FAIL"}`
                        : `Adversarial Negative Control: ${negPassed ? "PASS" : "FAIL"}`}
                    </span>
                    <span className="muted small mono">{negFlagged.join(" · ")}</span>
                  </div>
                )}

                {expandedResult && (
                  <div style={{ marginTop: 14, paddingTop: 12, borderTop: "1px solid var(--line)" }}>
                    <div className="row" style={{ justifyContent: "space-between", marginBottom: 6 }}>
                      <strong>
                        {isZh
                          ? `[${expandedResult.label}] 实测指纹遥测与 ${expandedResult.checks.length} 项逐条校验明细`
                          : `[${expandedResult.label}] Measured Telemetry & ${expandedResult.checks.length} Check Breakdown`}
                      </strong>
                      <span className="mono muted small">{expandedResult.mode}</span>
                    </div>
                    <TelemetryGrid measured={expandedResult.measured} isZh={isZh} />
                    <ChecksList checks={expandedResult.checks} isZh={isZh} />
                  </div>
                )}
              </>
            ) : (
              <p className="muted small" style={{ margin: "8px 0 0" }}>
                {isZh
                  ? "点击右上角「运行实机全量审计 (21项×3端)」真实启动 Camoufox C++ 内核检验全部运行时指纹与 Pre-TLS 请求头。"
                  : "Click Run Live 21-Check Audit to launch real Camoufox C++ instances and verify all runtime + Pre-TLS vectors."}
              </p>
            )}
          </div>

          {/* Panel 2: Single Saved Profile Deep Live + Recorded Audit */}
          <div className="donut-panel">
            <div className="donut-panel-head" style={{ flexWrap: "wrap", gap: 10 }}>
              <div>
                <h3>
                  {isZh
                    ? "单环境实机全维度指纹 + 跨会话零漂移账本 + Pre-TLS 录制审计"
                    : "Single Profile Live Fingerprint, Consistency Ledger & Pre-TLS Audit"}
                </h3>
                <p className="muted small" style={{ margin: "2px 0 0" }}>
                  {isZh
                    ? "针对任意已保存账号环境（如 #98），按其绑定的 SKU 预设、代理中继、时区与语言启动真实 Camoufox 录制会话，检验期望值与实测值一致性，并生成可回放的 SHA-256 签名流量包。"
                    : "Audits any saved profile with its exact SKU preset, proxy relay, timezone & locale, verifying Canvas/WebGL zero-drift ledger and recording Pre-TLS wire traffic for replay."}
                </p>
              </div>
            </div>

            <div className="row" style={{ gap: 8, marginTop: 12, flexWrap: "wrap" }}>
              <select
                style={{ minWidth: 260 }}
                value={selectedAuditProfileId}
                onChange={(e) => setSelectedAuditProfileId(e.target.value)}
              >
                {savedProfiles.map((p) => (
                  <option key={p.id} value={p.id}>
                    {p.serial_number != null ? `#${p.serial_number} · ` : ""}
                    {p.account_email || p.name} ({p.proxy?.country || "Direct"} · {p.timezone || "Auto TZ"} · {p.persona_id})
                  </option>
                ))}
              </select>
              <input
                style={{ flex: 1, minWidth: 240 }}
                placeholder={
                  isZh
                    ? "可选审计目标 URL（留空使用本地回环 Pre-TLS Wire Echo 探针；也可填 https://policies.google.com/terms 走代理实测）"
                    : "Optional target URL (blank uses local loopback Pre-TLS Wire Echo probe)"
                }
                value={auditTargetUrl}
                onChange={(e) => setAuditTargetUrl(e.target.value)}
              />
              <button
                className="primary"
                disabled={singleAuditBusy || !selectedAuditProfileId}
                onClick={() => void runSingleProfileAudit()}
              >
                {singleAuditBusy
                  ? isZh ? "正在实机录制审计..." : "Auditing Profile..."
                  : isZh ? "实机审计并录制该环境" : "Audit & Record Profile"}
              </button>
            </div>

            {singleAuditResult && (
              <div style={{ marginTop: 14 }}>
                <div className="donut-neg-bar" style={{ flexWrap: "wrap", gap: 10 }}>
                  <span className={`donut-pill ${singleAuditResult.passed ? "donut-pill-success" : "donut-pill-failed"}`}>
                    <span className="donut-dot" />
                    {singleAuditResult.serialNumber != null ? `#${singleAuditResult.serialNumber} ` : ""}
                    {singleAuditResult.accountEmail || singleAuditResult.profileName}: {singleAuditResult.passed ? "21/21 PASS" : `SCORE ${singleAuditResult.score}`}
                  </span>
                  <span className={`donut-pill ${singleAuditResult.integrity?.valid ? "donut-pill-success" : "donut-pill-failed"}`}>
                    SHA-256 哈希链: {singleAuditResult.integrity?.valid ? `VALID (${singleAuditResult.integrity.eventCount ?? 0} events)` : "INVALID"}
                  </span>
                  {singleAuditResult.ledgerResult && (
                    <span className={`donut-pill ${singleAuditResult.ledgerResult.passed !== false ? "donut-pill-success" : "donut-pill-failed"}`}>
                      Canvas/WebGL 账本漂移: Hamming={singleAuditResult.ledgerResult.hammingDistance ?? 0}
                    </span>
                  )}
                  <button
                    className="linky"
                    onClick={() => {
                      setSelectedReplayProfileId(singleAuditResult.profileId);
                      setTab("traffic");
                    }}
                  >
                    {isZh ? "查看本次录制的 Pre-TLS Wire 报文回放 →" : "Open Pre-TLS Wire Replay ->"}
                  </button>
                </div>

                <div className="donut-table-box" style={{ marginTop: 10 }}>
                  <table className="grid">
                    <thead>
                      <tr>
                        <th>{isZh ? "指纹对账维度" : "Dimension"}</th>
                        <th>{isZh ? "环境配置期望值" : "Expected"}</th>
                        <th>{isZh ? "内核实测观测值" : "Observed"}</th>
                        <th>{isZh ? "状态" : "Match"}</th>
                      </tr>
                    </thead>
                    <tbody>
                      {singleAuditResult.comparisons.map((cmp) => (
                        <tr key={cmp.field}>
                          <td className="small">{cmp.field}</td>
                          <td className="mono small">{cmp.expected}</td>
                          <td className="mono small">{cmp.observed}</td>
                          <td>
                            <span className={`donut-pill ${cmp.matched ? "donut-pill-success" : "donut-pill-failed"}`}>
                              {cmp.matched ? "MATCH" : "MISMATCH"}
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>

                <TelemetryGrid measured={singleAuditResult.measured} isZh={isZh} />
                <ChecksList checks={singleAuditResult.checks} isZh={isZh} />
              </div>
            )}
          </div>

          {/* Panel 3: 37 SKU Presets */}
          <div className="donut-panel">
            <div className="donut-panel-head" style={{ flexWrap: "wrap", gap: 10 }}>
              <div>
                <h3>
                  {isZh
                    ? `SKU 实机硬件预设目录 (${filteredPresets.length}/${presets.length})`
                    : `SKU-Verified Hardware Presets (${filteredPresets.length}/${presets.length})`}
                </h3>
                <p className="muted small" style={{ margin: "2px 0 0" }}>
                  {isZh
                    ? "覆盖 Apple Silicon M1–M5、Intel Mac、ThinkPad、Dell XPS、Surface、ROG、Razer 等真机参数。"
                    : "Apple Silicon M1–M5, Intel Macs, ThinkPad, XPS, Surface, ROG, Razer and Linux workstations."}
                </p>
              </div>
              <div className="row" style={{ gap: 8 }}>
                <div className="segmented">
                  {(["all", "macos", "windows", "linux"] as const).map((osKey) => (
                    <button
                      key={osKey}
                      aria-pressed={osFilter === osKey}
                      onClick={() => setOsFilter(osKey)}
                    >
                      {osKey === "all" ? (isZh ? "全部" : "All") : osKey}
                    </button>
                  ))}
                </div>
                <input
                  style={{ width: 200 }}
                  placeholder={isZh ? "搜索机型 / CPU / GPU..." : "Search model / CPU / GPU..."}
                  value={presetQuery}
                  onChange={(e) => setPresetQuery(e.target.value)}
                />
              </div>
            </div>

            <div className="donut-preset-grid">
              {filteredPresets.map((p) => (
                <div key={p.presetId} className={`donut-preset-card donut-preset-${p.os}`}>
                  <div className="donut-preset-top">
                    <strong className="ellipsis" title={p.deviceModel}>{p.deviceModel}</strong>
                    <span className={`donut-os-badge donut-os-badge-${p.os}`}>{p.os}</span>
                  </div>
                  <div className="muted small mono ellipsis" title={p.presetId}>{p.presetId}</div>
                  <div className="donut-spec-chips">
                    <span className="donut-chip">{p.hardwareConcurrency}T</span>
                    <span className="donut-chip">{p.ramGb} GB</span>
                    <span className="donut-chip">{p.storageGb} GB</span>
                    <span className="donut-chip">{p.screen.width}×{p.screen.height}@{p.screen.devicePixelRatio}x</span>
                  </div>
                  <div className="donut-preset-specs">
                    <span className="ellipsis" title={p.cpuModel}>CPU · {p.cpuModel}</span>
                    <span className="ellipsis" title={p.webgl.unmaskedRenderer}>GPU · {p.gpuModel}</span>
                  </div>
                  <button className="donut-preset-cta" onClick={() => onCreateFromPreset(p)}>
                    {isZh ? "+ 用此预设新建环境" : "+ Create Profile"}
                  </button>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {tab === "traffic" && (
        <div className="donut-lab-body">
          <div className="donut-panel">
            <div className="donut-panel-head" style={{ flexWrap: "wrap", gap: 10 }}>
              <div>
                <h3>
                  {isZh
                    ? "Pre-TLS 明文报文录制、SHA-256 防篡改校验 & 交互式回放审计台"
                    : "Pre-TLS Wire Recording, Cryptographic Hash-Chain & Transaction Replay Auditor"}
                </h3>
                <p className="muted small mono" style={{ margin: "2px 0 0" }}>
                  {traffic?.profilesDir || overview?.profilesDir}
                </p>
              </div>
              <div className="row" style={{ gap: 8 }}>
                {selectedReplayProfileId && (
                  <button onClick={() => void exportHarNow()}>
                    {isZh ? "导出 HAR 1.2" : "Export HAR"}
                  </button>
                )}
                <button className="primary" disabled={trafficBusy} onClick={() => void refreshTraffic()}>
                  {trafficBusy ? (isZh ? "刷新中..." : "Refreshing...") : (isZh ? "刷新录制归因库" : "Refresh Captures")}
                </button>
              </div>
            </div>

            {harNotice && (
              <div className="verdict good" style={{ marginTop: 10 }}>
                {harNotice}
              </div>
            )}

            <div className="donut-traffic-hero">
              <div className="donut-traffic-metrics">
                <div>
                  <span className="muted small">{isZh ? "累计捕获事件" : "Events"}</span>
                  <strong>{traffic?.totalEvents ?? 0}</strong>
                </div>
                <div>
                  <span className="muted small">{isZh ? "累计负载体积" : "Volume"}</span>
                  <strong>{formatBytes(traffic?.totalBytes ?? 0)}</strong>
                </div>
                <div>
                  <span className="muted small">{isZh ? "含录制环境数" : "Recorded Profiles"}</span>
                  <strong>{trafficProfiles.length || traffic?.profileCaptures || 0}</strong>
                </div>
              </div>
              <div style={{ flex: 1, minWidth: 220 }}>
                <BandwidthSparkline data={traffic?.buckets || []} gradientId="lab-traffic-spark" height={64} />
              </div>
            </div>

            {/* Profile Selector & Filters */}
            <div className="row" style={{ gap: 8, marginTop: 12, flexWrap: "wrap" }}>
              <select
                style={{ minWidth: 260 }}
                value={selectedReplayProfileId}
                onChange={(e) => {
                  setActiveWireDump(null);
                  setSelectedReplayProfileId(e.target.value);
                }}
              >
                <option value="">{isZh ? "— 选择要回放审计的环境捕获库 —" : "— Select Recorded Profile —"}</option>
                {trafficProfiles.map((tp) => (
                  <option key={tp.profileId} value={tp.profileId}>
                    {tp.serialNumber != null ? `#${tp.serialNumber} · ` : ""}
                    {tp.accountEmail || tp.profileName} · req={tp.totals?.totalRequests ?? 0} res={tp.totals?.totalResponses ?? 0}
                    {tp.recordingActive ? " [🔴 实时录制中]" : ""}
                  </option>
                ))}
              </select>
              <input
                style={{ width: 150 }}
                placeholder={isZh ? "域名过滤 (如 google)" : "Domain filter"}
                value={filterDomain}
                onChange={(e) => setFilterDomain(e.target.value)}
              />
              <select style={{ width: 120 }} value={filterStatus} onChange={(e) => setFilterStatus(e.target.value)}>
                <option value="">{isZh ? "全部状态码" : "All Status"}</option>
                <option value="2xx">2xx OK</option>
                <option value="3xx">3xx Redirect</option>
                <option value="4xx">4xx Client Err</option>
                <option value="5xx">5xx Server Err</option>
                <option value="0">{isZh ? "0 安全拦截" : "0 Blocked"}</option>
              </select>
              <select style={{ width: 140 }} value={filterPlatform} onChange={(e) => setFilterPlatform(e.target.value)}>
                <option value="">{isZh ? "全部反爬平台" : "All Platforms"}</option>
                <option value="google">Google BotGuard</option>
                <option value="cloudflare">Cloudflare</option>
                <option value="arkose">Arkose BDA</option>
                <option value="meta">Meta</option>
                <option value="twitter">Twitter / X</option>
                <option value="bytedance">ByteDance</option>
              </select>
              <input
                style={{ width: 140 }}
                placeholder={isZh ? "步骤 (actionStep)" : "Step filter"}
                value={filterStep}
                onChange={(e) => setFilterStep(e.target.value)}
              />
              {savedProfiles.length > 0 && (
                <button
                  onClick={() => void launchProfileForRecording(selectedReplayProfileId || savedProfiles[0].id)}
                  title={isZh ? "打开选中环境的浏览器窗口并实时录制全部 Pre-TLS 流量" : "Launch browser window with live Pre-TLS recording"}
                >
                  {isZh ? "▶ 启动实时录制窗口" : "▶ Launch Recorded Window"}
                </button>
              )}
            </div>

            {trafficDetail ? (
              <div style={{ marginTop: 14 }}>
                {/* SHA-256 Cryptographic Integrity Banner */}
                <div className="donut-neg-bar" style={{ flexWrap: "wrap", gap: 10 }}>
                  <span className={`donut-pill ${trafficDetail.integrity?.valid ? "donut-pill-success" : "donut-pill-failed"}`}>
                    <span className="donut-dot" />
                    {trafficDetail.integrity?.valid
                      ? isZh ? "SHA-256 事件哈希链 & 载荷清单校验通过" : "SHA-256 Hash Chain Verified"
                      : isZh ? "完整性校验未通过 / 录制进行中" : "Integrity Unverified / Recording"}
                  </span>
                  <span className="mono muted small">
                    events={trafficDetail.integrity?.eventCount ?? trafficDetail.eventsCount} · payloads={trafficDetail.integrity?.verifiedPayloads ?? 0} · head={(trafficDetail.integrity?.chainHeadHash || "").slice(0, 16)}…
                  </span>
                  {trafficDetail.artifacts?.sslKeyLogPath && <span className="donut-chip mono">SSLKEYLOGFILE ✓</span>}
                  {trafficDetail.artifacts?.preTlsWireLogPath && <span className="donut-chip mono">pre-tls-wire.log ✓</span>}
                  {trafficDetail.artifacts?.neckoMozLogPath && <span className="donut-chip mono">necko-pre-tls.moz_log ✓</span>}
                </div>

                {/* Sub-tabs */}
                <div className="segmented" style={{ marginTop: 12 }}>
                  <button
                    aria-pressed={replaySubTab === "transactions"}
                    onClick={() => setReplaySubTab("transactions")}
                  >
                    {isZh
                      ? `事务与 Wire 回放 (${trafficDetail.transactions.length})`
                      : `Transactions & Wire Replay (${trafficDetail.transactions.length})`}
                  </button>
                  <button
                    aria-pressed={replaySubTab === "signatures"}
                    onClick={() => setReplaySubTab("signatures")}
                  >
                    {isZh
                      ? `反爬平台特征 (${trafficDetail.platformSignatures.totalDetected})`
                      : `Anti-Bot Signatures (${trafficDetail.platformSignatures.totalDetected})`}
                  </button>
                  <button
                    aria-pressed={replaySubTab === "cookies"}
                    onClick={() => setReplaySubTab("cookies")}
                  >
                    {isZh
                      ? `Cookie 血缘 (${trafficDetail.cookies.length} · 令牌 ${trafficDetail.antiBotTokenCount})`
                      : `Cookie Lineage (${trafficDetail.cookies.length})`}
                  </button>
                  <button
                    aria-pressed={replaySubTab === "anomalies"}
                    onClick={() => setReplaySubTab("anomalies")}
                  >
                    {isZh
                      ? `异常与安全拦截 (${trafficDetail.anomalies.length})`
                      : `Anomalies & Blocks (${trafficDetail.anomalies.length})`}
                  </button>
                </div>

                {replaySubTab === "transactions" && (
                  <div className="donut-table-box" style={{ marginTop: 10 }}>
                    <table className="grid">
                      <thead>
                        <tr>
                          <th>Correlation ID</th>
                          <th>{isZh ? "方法 / 状态" : "Method / Status"}</th>
                          <th>URL</th>
                          <th>{isZh ? "归因步骤 / 触发动作" : "Step / UI Trigger"}</th>
                          <th>{isZh ? "操作" : "Replay"}</th>
                        </tr>
                      </thead>
                      <tbody>
                        {trafficDetail.transactions.map((tx) => (
                          <tr
                            key={tx.correlationId}
                            style={{
                              cursor: "pointer",
                              background: activeWireDump?.correlationId === tx.correlationId ? "var(--hover)" : undefined,
                            }}
                            onClick={() => void openWireReplay(trafficDetail.profileId, tx.correlationId)}
                          >
                            <td className="mono small">{tx.correlationId}</td>
                            <td className="mono small">
                              {tx.method || "GET"} {tx.status ?? tx.failureText ?? "PENDING"}
                            </td>
                            <td className="mono small ellipsis" style={{ maxWidth: 340 }} title={tx.url || ""}>
                              {tx.url || "—"}
                            </td>
                            <td className="small muted">
                              {tx.actionStep || "browse"}
                              {tx.triggerAction?.actionType ? ` · ${tx.triggerAction.actionType}:${tx.triggerAction.target || ""}` : ""}
                            </td>
                            <td>
                              <button
                                type="button"
                                className="acctMiniBtn"
                                disabled={wireDumpBusy}
                                onClick={(e) => {
                                  e.stopPropagation();
                                  void openWireReplay(trafficDetail.profileId, tx.correlationId);
                                }}
                              >
                                {isZh ? "回放 Wire 报文" : "Replay Wire"}
                              </button>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}

                {replaySubTab === "signatures" && (
                  <div className="donut-table-box" style={{ marginTop: 10 }}>
                    {trafficDetail.platformSignatures.signatures.length > 0 ? (
                      <table className="grid">
                        <thead>
                          <tr>
                            <th>{isZh ? "平台" : "Platform"}</th>
                            <th>{isZh ? "特征参数 / 位置" : "Signature / Location"}</th>
                            <th>{isZh ? "掩码预览 & SHA-256" : "Masked & SHA-256"}</th>
                            <th>{isZh ? "因果步骤 / 触发器" : "Step / Trigger"}</th>
                            <th>{isZh ? "报文回放" : "Replay"}</th>
                          </tr>
                        </thead>
                        <tbody>
                          {trafficDetail.platformSignatures.signatures.map((sig, i) => (
                            <tr key={`${sig.correlationId}-${sig.signatureName}-${i}`}>
                              <td><span className="donut-os-badge">{sig.platform}</span></td>
                              <td className="mono small">{sig.signatureName} ({sig.location})</td>
                              <td className="mono small" title={sig.valueSha256 || ""}>
                                {sig.maskedPreview || "—"} · {(sig.valueSha256 || "").slice(0, 12)}
                              </td>
                              <td className="small muted">{sig.actionStep || "—"}</td>
                              <td>
                                {sig.correlationId && (
                                  <button
                                    type="button"
                                    className="acctMiniBtn"
                                    onClick={() => void openWireReplay(trafficDetail.profileId, sig.correlationId!)}
                                  >
                                    {isZh ? "回放报文" : "Wire Dump"}
                                  </button>
                                )}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    ) : (
                      <p className="muted small" style={{ padding: 12 }}>
                        {isZh ? "当前筛选条件下未检测到 BotGuard / Turnstile / Arkose 等平台反爬特征令牌。" : "No anti-bot platform signatures detected in this capture."}
                      </p>
                    )}
                  </div>
                )}

                {replaySubTab === "cookies" && (
                  <div className="donut-table-box" style={{ marginTop: 10 }}>
                    {trafficDetail.cookies.length > 0 ? (
                      <table className="grid">
                        <thead>
                          <tr>
                            <th>Cookie</th>
                            <th>{isZh ? "域 / 属性" : "Domain / Flags"}</th>
                            <th>{isZh ? "首次写入步骤" : "First Set Step"}</th>
                            <th>{isZh ? "变更 / 发送次数" : "Mutations / Sent"}</th>
                            <th>SHA-256</th>
                            <th>{isZh ? "溯源回放" : "Origin Wire"}</th>
                          </tr>
                        </thead>
                        <tbody>
                          {trafficDetail.cookies.map((ck, i) => (
                            <tr key={`${ck.name}-${ck.domain}-${i}`}>
                              <td className="mono small">
                                <strong>{ck.name}</strong>{" "}
                                {ck.isAntiBotToken && (
                                  <span className="donut-pill donut-pill-manual" style={{ marginLeft: 4 }}>
                                    ANTI-BOT/AUTH
                                  </span>
                                )}
                              </td>
                              <td className="mono small muted">
                                {ck.domain || "host"} · {ck.sameSite || "—"}
                                {ck.httpOnly ? " · HttpOnly" : ""}
                                {ck.secure ? " · Secure" : ""}
                              </td>
                              <td className="small muted">{ck.firstSetAtStep || "—"}</td>
                              <td className="mono small">mut={ck.mutationsCount ?? 0} · sent={ck.sentCount ?? 0}</td>
                              <td className="mono small">{(ck.lastValueSha256 || "").slice(0, 14) || "—"}</td>
                              <td>
                                {ck.firstSetByCorrelationId && (
                                  <button
                                    type="button"
                                    className="acctMiniBtn"
                                    onClick={() => void openWireReplay(trafficDetail.profileId, ck.firstSetByCorrelationId!)}
                                  >
                                    {isZh ? "Set-Cookie 报文" : "Wire Dump"}
                                  </button>
                                )}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    ) : (
                      <p className="muted small" style={{ padding: 12 }}>
                        {isZh ? "当前捕获中暂无 Set-Cookie / Cookie 血缘记录。" : "No cookie lineage records in this capture."}
                      </p>
                    )}
                  </div>
                )}

                {replaySubTab === "anomalies" && (
                  <div className="donut-table-box" style={{ marginTop: 10 }}>
                    {trafficDetail.anomalies.length > 0 ? (
                      <table className="grid">
                        <thead>
                          <tr>
                            <th>{isZh ? "级别 / 类型" : "Severity / Type"}</th>
                            <th>{isZh ? "状态 / 原因" : "Status / Reason"}</th>
                            <th>URL</th>
                            <th>{isZh ? "回放" : "Replay"}</th>
                          </tr>
                        </thead>
                        <tbody>
                          {trafficDetail.anomalies.map((an, i) => (
                            <tr key={`${an.correlationId}-${an.type}-${i}`}>
                              <td className="mono small">
                                <span className="donut-pill donut-pill-failed">{an.severity || "warn"}</span> {an.type}
                              </td>
                              <td className="mono small">{an.status ?? "BLOCK"} · {an.failureText || an.reason || "—"}</td>
                              <td className="mono small ellipsis" style={{ maxWidth: 320 }} title={an.url || ""}>{an.url || "—"}</td>
                              <td>
                                {an.correlationId && (
                                  <button
                                    type="button"
                                    className="acctMiniBtn"
                                    onClick={() => void openWireReplay(trafficDetail.profileId, an.correlationId!)}
                                  >
                                    {isZh ? "回放" : "Replay"}
                                  </button>
                                )}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    ) : (
                      <p className="muted small" style={{ padding: 12 }}>
                        {isZh ? "✅ 0 异常：未发现 4xx/5xx 风控拦截、请求头泄漏或本地端口扫描探测。" : "0 anomalies or security blocks detected."}
                      </p>
                    )}
                  </div>
                )}

                {/* Interactive Pre-TLS Egress + Post-TLS Ingress Wire Dump Viewer */}
                {activeWireDump && (
                  <div style={{ marginTop: 14 }}>
                    <div className="row" style={{ justifyContent: "space-between", alignItems: "center" }}>
                      <strong>
                        {isZh
                          ? `🔍 Pre-TLS 原始出站 + 入站报文完整重建回放 (${activeWireDump.correlationId})`
                          : `Pre-TLS Egress + Post-TLS Ingress Wire Reconstruction (${activeWireDump.correlationId})`}
                      </strong>
                      <button className="linky" onClick={() => setActiveWireDump(null)}>
                        {isZh ? "收起报文回放 ×" : "Close ×"}
                      </button>
                    </div>
                    <pre className="donut-wire-viewer">{activeWireDump.wireDump || JSON.stringify(activeWireDump, null, 2)}</pre>
                  </div>
                )}
              </div>
            ) : (
              <p className="muted small" style={{ marginTop: 12 }}>
                {isZh
                  ? "在上方选择已有捕获的环境，或在「实机全量指纹审计」对任意环境点击「实机审计并录制」，或直接打开环境窗口浏览页面（系统已默认启用 Pre-TLS 实时录制），即可在此逐笔回放 HTTP 原始报文、BotGuard 特征与 Cookie 血缘。"
                  : "Select a recorded profile above, run Single Profile Audit, or open any profile window to record and replay Pre-TLS wire transactions."}
              </p>
            )}
          </div>
        </div>
      )}

      {tab === "adspower" && (
        <div className="donut-lab-body">
          <div className="donut-panel">
            <div className="donut-panel-head">
              <div>
                <h3>{isZh ? "AdsPower 本地缓存只读审计 & 一键修复迁移" : "AdsPower Local Cache Auditor & Auto-Healer"}</h3>
                <p className="muted small" style={{ margin: "2px 0 0" }}>
                  {isZh
                    ? "解码本地 AdsPower 缓存（不读取任何 Cookie/密码/Token），检测硬件参数矛盾并一键修复为 100/100 一致性的 Camoufox 预设。"
                    : "Decodes local AdsPower cache metadata (without touching cookies/passwords/tokens) and heals broken SKU fingerprints into coherent Camoufox profiles."}
                </p>
              </div>
            </div>

            <div className="row" style={{ gap: 8, marginTop: 12 }}>
              <input
                style={{ flex: 1 }}
                placeholder={isZh ? "输入本地 AdsPower 缓存目录绝对路径（例如 /path/to/cache）" : "/path/to/adspower/cache"}
                value={adsCacheDir}
                onChange={(e) => setAdsCacheDir(e.target.value)}
              />
              <button className="primary" disabled={adsBusy || !adsCacheDir.trim()} onClick={() => void runAdsAudit()}>
                {adsBusy ? (isZh ? "扫描中..." : "Scanning...") : (isZh ? "审计目录" : "Audit Directory")}
              </button>
              {adsAudit && adsAudit.profiles.length > 0 && (
                <button disabled={adsBusy} onClick={() => void healAllAds()}>
                  {isZh ? `一键修复导入 (${adsAudit.profiles.length})` : `Heal & Import (${adsAudit.profiles.length})`}
                </button>
              )}
            </div>

            {adsMessage && (
              <div className="verdict good" style={{ marginTop: 10 }}>
                {adsMessage}
              </div>
            )}

            {adsAudit && (
              <div style={{ marginTop: 14 }}>
                <div className="row muted small" style={{ gap: 14, marginBottom: 8 }}>
                  <span>{isZh ? `扫描目录: ${adsAudit.totalScanned}` : `Scanned: ${adsAudit.totalScanned}`}</span>
                  <span>{isZh ? `解码环境: ${adsAudit.totalDecoded}` : `Decoded: ${adsAudit.totalDecoded}`}</span>
                  <span className="donut-text-ok">{isZh ? `通过: ${adsAudit.passedCount}` : `Passed: ${adsAudit.passedCount}`}</span>
                  <span>{isZh ? `存在冲突: ${adsAudit.failedCount}` : `Failed: ${adsAudit.failedCount}`}</span>
                </div>
                {adsAudit.profiles.length > 0 ? (
                  <div className="donut-table-box">
                    <table className="grid">
                      <thead>
                        <tr>
                          <th>FBCC ID</th>
                          <th>{isZh ? "平台 / 设备" : "Platform / Device"}</th>
                          <th>{isZh ? "核心 / 内存" : "Cores / RAM"}</th>
                          <th>GPU</th>
                          <th>{isZh ? "审计状态" : "Status"}</th>
                          <th>{isZh ? "建议修复预设" : "Healed Preset"}</th>
                        </tr>
                      </thead>
                      <tbody>
                        {adsAudit.profiles.map((item) => (
                          <tr key={item.profileDirName}>
                            <td className="mono small">{item.fbccId}</td>
                            <td className="small">{item.platform || "—"} · {item.deviceName || "—"}</td>
                            <td className="mono small">{item.cores ?? "?"}T / {item.deviceMemoryGb ?? "?"}GB</td>
                            <td className="small muted">{item.renderer || "—"}</td>
                            <td>
                              <span className={`donut-pill ${item.passed ? "donut-pill-success" : "donut-pill-failed"}`}>
                                <span className="donut-dot" />
                                {item.status}
                              </span>
                            </td>
                            <td className="mono small" title={(item.healed?.repairsApplied || []).join(" · ")}>
                              {item.healed?.healedPresetId || item.healed?.healedProfile?.presetId || item.healed?.preset?.presetId || "—"}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                ) : (
                  <p className="muted small">{isZh ? "该目录下未解码到 AdsPower 环境配置。" : "No decodable AdsPower profiles found."}</p>
                )}
              </div>
            )}
          </div>
        </div>
      )}

      {tab === "config" && (
        <div className="donut-lab-body">
          <div className="donut-panel">
            <div className="donut-panel-head">
              <div>
                <h3>{isZh ? "Gmail 注册人工接管记录 (results.json / summary.json)" : "Signup Handoff History"}</h3>
                <p className="muted small mono" style={{ margin: "2px 0 0" }}>
                  {history?.stateDir}
                </p>
              </div>
              <button onClick={() => void loadAll()}>{isZh ? "刷新" : "Refresh"}</button>
            </div>

            {history?.summary?.stats && (
              <div className="donut-neg-bar" style={{ marginTop: 10 }}>
                <span className="small">
                  {isZh ? "最近汇总:" : "Latest summary:"} total={history.summary.stats.total ?? 0} ·
                  completed={history.summary.stats.completed ?? 0} ·
                  manual={history.summary.stats.manual ?? 0} ·
                  failed={history.summary.stats.failed ?? 0}
                </span>
              </div>
            )}

            {history && history.results.length > 0 ? (
              <div className="donut-table-box" style={{ marginTop: 10 }}>
                <table className="grid">
                  <thead>
                    <tr>
                      <th>{isZh ? "时间" : "Time"}</th>
                      <th>{isZh ? "环境" : "Profile"}</th>
                      <th>{isZh ? "状态 / 人工接管" : "Handoff Status"}</th>
                      <th>{isZh ? "清理状态" : "Cleanup"}</th>
                      <th>{isZh ? "代理 IP" : "Proxy IP"}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {history.results.map((r, idx) => (
                      <tr key={r.resultId || `${r.timestamp}-${idx}`}>
                        <td className="mono small">{r.timestamp ? new Date(r.timestamp).toLocaleString() : "—"}</td>
                        <td className="mono small">{r.profileId || r.profileType || "—"}</td>
                        <td><ProfileHandoffStatus item={r} compact /></td>
                        <td className="mono small">{r.profileCleanup || "—"}</td>
                        <td className="mono small">{r.proxyIP || "—"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <p className="muted small" style={{ marginTop: 10 }}>
                {isZh ? "暂无运行记录（执行 npm start 后会写入状态目录 results.json）。" : "No run records yet."}
              </p>
            )}
          </div>

          <div className="donut-panel">
            <div className="donut-panel-head">
              <div>
                <h3>{isZh ? "状态目录 .env 运行配置（0600 私有权限）" : "State Directory .env Configuration"}</h3>
                <p className="muted small mono" style={{ margin: "2px 0 0" }}>
                  {envCfg?.path}
                </p>
              </div>
              <div className="row" style={{ gap: 8 }}>
                {envSaved && <span className="donut-pill donut-pill-success"><span className="donut-dot" />{isZh ? "已保存" : "Saved"}</span>}
                <button className="primary" onClick={() => void saveEnv()}>
                  {isZh ? "保存 .env 配置" : "Save .env"}
                </button>
              </div>
            </div>

            {envCfg && (
              <div className="donut-env-grid">
                {envCfg.keys.map((key) => (
                  <label key={key} className="donut-env-field">
                    <span className="mono small muted">{key}</span>
                    <input
                      value={envDraft[key] ?? ""}
                      placeholder={key === "PROFILE_SERVICE" ? "camoufox" : ""}
                      onChange={(e) => setEnvDraft((cur) => ({ ...cur, [key]: e.target.value }))}
                    />
                  </label>
                ))}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
