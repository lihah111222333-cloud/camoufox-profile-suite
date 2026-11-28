// SPDX-License-Identifier: AGPL-3.0-or-later
// UI design pattern selectively absorbed from Donut Browser (metadata cards + sparkline strip).

import type { SuiteOverview } from "../../api";
import { BandwidthSparkline } from "./BandwidthSparkline";

function formatBytes(bytes: number): string {
  if (!bytes || bytes < 1024) return `${bytes || 0} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

export function SuiteSummaryBar({
  overview,
  isZh,
  onOpenLab,
}: {
  overview: SuiteOverview | null;
  isZh: boolean;
  onOpenLab: (tab?: "coherence" | "traffic" | "adspower" | "config") => void;
}) {
  if (!overview) return null;

  const isRealCamoufox = Boolean(overview.isAntidetectEngine ?? (overview.browserLauncher?.kind === "camoufox"));
  const isInstalling = overview.baselineStatus === "installing";

  const lastMode = overview.lastCoherence?.mode || overview.lastCoherence?.report?.mode || "";
  const isLiveAudit = lastMode.startsWith("live-");
  const coherencePassed = overview.lastCoherence?.report?.overallPassed;

  let coherenceText: string;
  let coherencePillClass = "donut-pill-manual";
  let coherencePillLabel = isZh ? "待实机验证" : "Pending Live";

  if (!overview.lastCoherence) {
    coherenceText = isZh ? "待运行" : "Not run";
  } else if (!isLiveAudit) {
    coherenceText = isZh ? "仅静态规则" : "Dry-Run Only";
    coherencePillClass = "donut-pill-manual";
    coherencePillLabel = isZh ? "需实机审计" : "Needs Live";
  } else if (coherencePassed === true) {
    coherenceText = "21 / 21";
    coherencePillClass = "donut-pill-success";
    coherencePillLabel = isZh ? "实机 PASS" : "LIVE PASS";
  } else {
    coherenceText = isZh ? "发现异常" : "ISSUES";
    coherencePillClass = "donut-pill-failed";
    coherencePillLabel = "FAIL";
  }

  return (
    <section className="donut-kpi-strip" aria-label={isZh ? "运行概览" : "Suite Overview"}>
      <button
        type="button"
        className="donut-kpi-card donut-kpi-coral"
        onClick={() => onOpenLab("coherence")}
      >
        <div className="donut-kpi-head">
          <span className="donut-kpi-label">{isZh ? "Camoufox 内核 & SKU 库" : "Camoufox Engine & SKUs"}</span>
          <span className="donut-kpi-icon donut-icon-coral" aria-hidden="true">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.9" strokeLinecap="round" strokeLinejoin="round">
              <rect x="4" y="4" width="16" height="16" rx="2" />
              <rect x="9" y="9" width="6" height="6" rx="1" />
              <path d="M9 1v3M15 1v3M9 20v3M15 20v3M20 9h3M20 14h3M1 9h3M1 14h3" />
            </svg>
          </span>
        </div>
        <div className="donut-kpi-value">
          <span>{overview.presetCount}</span>
          <span
            className={`donut-pill ${
              isRealCamoufox
                ? "donut-pill-success"
                : isInstalling
                  ? "donut-pill-manual"
                  : "donut-pill-failed"
            }`}
          >
            <span className="donut-dot" />
            {isRealCamoufox
              ? isZh ? "Camoufox C++ 就绪" : "Camoufox C++ Ready"
              : isInstalling
                ? isZh ? "内核安装中…" : "Installing…"
                : overview.browserLauncher
                  ? isZh ? "降级模式 (无隔离)" : "Degraded Fallback"
                  : isZh ? "未检出内核" : "Missing Core"}
          </span>
        </div>
        <div className="donut-kpi-sub">
          {isZh
            ? `${overview.browserLauncher?.label || (isInstalling ? "正在后台拉取 Camoufox 基线包" : overview.profileService)} · 运行 ${overview.runningCount}/${overview.profileCount}`
            : `${overview.browserLauncher?.label || overview.profileService} · Active ${overview.runningCount}/${overview.profileCount}`}
        </div>
      </button>

      <button
        type="button"
        className="donut-kpi-card donut-kpi-emerald"
        onClick={() => onOpenLab("coherence")}
      >
        <div className="donut-kpi-head">
          <span className="donut-kpi-label">{isZh ? "21 项实机指纹 + Wire 审计" : "21-Check Live + Wire Audit"}</span>
          <span className="donut-kpi-icon donut-icon-emerald" aria-hidden="true">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10Z" />
              <path d="m9 12 2 2 4-4" />
            </svg>
          </span>
        </div>
        <div className="donut-kpi-value">
          <span className={isLiveAudit && coherencePassed === true ? "donut-text-ok" : ""}>{coherenceText}</span>
          <span className={`donut-pill ${coherencePillClass}`}>
            <span className="donut-dot" />
            {coherencePillLabel}
          </span>
        </div>
        <div className="donut-kpi-sub">
          {isZh
            ? "17 维 DOM/Worker/WebGL/字体 + 4 维 Pre-TLS"
            : "17 DOM/Worker/WebGL/Fonts + 4 Pre-TLS Wire"}
        </div>
      </button>

      <button
        type="button"
        className="donut-kpi-card donut-kpi-cyan"
        onClick={() => onOpenLab("traffic")}
      >
        <div className="donut-kpi-head">
          <span className="donut-kpi-label">{isZh ? "Pre-TLS 录制与回放审计" : "Pre-TLS Recording & Replay"}</span>
          <span className="donut-kpi-icon donut-icon-cyan" aria-hidden="true">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.9" strokeLinecap="round" strokeLinejoin="round">
              <path d="M22 12h-4l-3 9L9 3l-3 9H2" />
            </svg>
          </span>
        </div>
        <div className="donut-kpi-spark-row">
          <div>
            <div className="donut-kpi-value">{overview.traffic.totalEvents}</div>
            <div className="donut-kpi-sub">
              {formatBytes(overview.traffic.totalBytes)} · {overview.traffic.profileCaptures}{" "}
              {isZh ? "个捕获库" : "captures"}
              {overview.recordingCount ? (isZh ? ` · 录制中 ${overview.recordingCount}` : ` · Rec ${overview.recordingCount}`) : ""}
            </div>
          </div>
          <div className="donut-kpi-spark-box">
            <BandwidthSparkline data={overview.traffic.buckets} gradientId="summary-spark" height={34} />
          </div>
        </div>
      </button>

      <button
        type="button"
        className="donut-kpi-card donut-kpi-violet"
        onClick={() => onOpenLab("config")}
      >
        <div className="donut-kpi-head">
          <span className="donut-kpi-label">{isZh ? "代理池与任务记录" : "Proxies & Handoffs"}</span>
          <span className="donut-kpi-icon donut-icon-violet" aria-hidden="true">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.9" strokeLinecap="round" strokeLinejoin="round">
              <circle cx="12" cy="12" r="9" />
              <path d="M3.6 9h16.8M3.6 15h16.8M12 3a13 13 0 0 1 0 18" />
            </svg>
          </span>
        </div>
        <div className="donut-kpi-value">
          <span>{overview.proxyCount}</span>
          <span className="muted small" style={{ fontWeight: 450 }}>
            {isZh ? `代理 · ${overview.recentResultsCount} 条历史` : `proxies · ${overview.recentResultsCount} runs`}
          </span>
        </div>
        <div className="donut-kpi-sub mono ellipsis" title={overview.stateDir}>
          {overview.stateDir}
        </div>
      </button>
    </section>
  );
}
