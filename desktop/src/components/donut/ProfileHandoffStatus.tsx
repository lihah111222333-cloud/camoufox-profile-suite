// SPDX-License-Identifier: AGPL-3.0-or-later
// UI design pattern selectively absorbed from Donut Browser (profile-handoff-status.tsx)
// Renders profile handoff & cleanup status pills for Gmail signup attempts and Camoufox sessions.

export type HandoffPhase = "success" | "manual" | "unconfirmed" | "failed";

export function classifyHandoff(item: {
  success?: boolean;
  errorCode?: string;
  errorStage?: string;
  profileCleanup?: string;
}): { phase: HandoffPhase; label: string; detail: string } {
  if (item.profileCleanup === "stop-unconfirmed" || item.profileCleanup === "pending") {
    return {
      phase: "unconfirmed",
      label: "清理待确认",
      detail: `profileCleanup=${item.profileCleanup}`,
    };
  }
  if (item.success) {
    return {
      phase: "success",
      label: "已完成",
      detail: item.profileCleanup === "stopped" ? "环境已确认关闭" : "已保存结果",
    };
  }
  if (item.errorCode === "MANUAL_SIGNUP_REQUIRED") {
    return {
      phase: "manual",
      label: "需人工接管",
      detail: item.profileCleanup === "stopped" ? "环境已安全关闭，请在受信任浏览器继续" : "等待人工接管",
    };
  }
  return {
    phase: "failed",
    label: item.errorCode || "执行失败",
    detail: item.errorStage ? `阶段: ${item.errorStage}` : "查看 summary.json 详情",
  };
}

export function ProfileHandoffStatus({
  item,
  compact = false,
}: {
  item: {
    success?: boolean;
    errorCode?: string;
    errorStage?: string;
    profileCleanup?: string;
  };
  compact?: boolean;
}) {
  const { phase, label, detail } = classifyHandoff(item);

  if (compact) {
    return (
      <span className={`donut-pill donut-pill-${phase}`} title={detail}>
        <span className="donut-dot" aria-hidden="true" />
        <span>{label}</span>
      </span>
    );
  }

  return (
    <div className={`donut-handoff-card donut-handoff-${phase}`}>
      <div className="donut-handoff-head">
        <span className={`donut-pill donut-pill-${phase}`}>
          <span className="donut-dot" aria-hidden="true" />
          <span>{label}</span>
        </span>
        {item.errorStage && <span className="muted small mono">{item.errorStage}</span>}
      </div>
      <p className="muted small" style={{ margin: "6px 0 0" }}>
        {detail}
      </p>
    </div>
  );
}
