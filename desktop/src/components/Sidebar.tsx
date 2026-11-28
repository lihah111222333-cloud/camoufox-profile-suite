// SPDX-License-Identifier: AGPL-3.0-or-later
// Adapted from Fury Browser (Copyright 2026 Bogdan Shapovalov and the Fury authors)
// Visual polish & icon navigation enhanced for Camoufox Studio.

import { useI18n } from "../i18n";
import { useState } from "react";
import type { Me, Project, Shell } from "../api";
import { useTheme } from "../theme";

export type View = "profiles" | "suiteLab" | "apiCli" | "sharedWithMe" | "proxies" | "extensions" | "bookmarks" | "assistants" | "trash" | "users";

function NavIcon({ view }: { view: View }) {
  const props = {
    width: 15,
    height: 15,
    viewBox: "0 0 24 24",
    fill: "none",
    stroke: "currentColor",
    strokeWidth: 1.8,
    strokeLinecap: "round" as const,
    strokeLinejoin: "round" as const,
    "aria-hidden": true,
    className: "navIcon",
  };
  switch (view) {
    case "profiles":
      return (
        <svg {...props}>
          <rect x="3" y="4" width="18" height="14" rx="2.5" />
          <path d="M8 21h8M12 18v3M7 9h4M7 13h10" />
        </svg>
      );
    case "suiteLab":
      return (
        <svg {...props}>
          <path d="M9 3h6M10 3v5.4L5.4 17a2.5 2.5 0 0 0 2.2 3.7h8.8a2.5 2.5 0 0 0 2.2-3.7L14 8.4V3" />
          <path d="M7.5 15h9" />
        </svg>
      );
    case "apiCli":
      return (
        <svg {...props}>
          <polyline points="4 17 10 11 4 5" />
          <line x1="12" y1="19" x2="20" y2="19" />
        </svg>
      );
    case "proxies":
      return (
        <svg {...props}>
          <circle cx="12" cy="12" r="9" />
          <path d="M3.6 9h16.8M3.6 15h16.8M12 3a13 13 0 0 1 0 18M12 3a13 13 0 0 0 0 18" />
        </svg>
      );
    case "extensions":
      return (
        <svg {...props}>
          <path d="M10 4a2 2 0 0 1 4 0v1h3a1 1 0 0 1 1 1v3h1a2 2 0 0 1 0 4h-1v4a1 1 0 0 1-1 1h-3v-1a2 2 0 0 0-4 0v1H7a1 1 0 0 1-1-1v-4H5a2 2 0 0 1 0-4h1V6a1 1 0 0 1 1-1h3V4Z" />
        </svg>
      );
    case "bookmarks":
      return (
        <svg {...props}>
          <path d="M6 4h12a1 1 0 0 1 1 1v16l-7-4-7 4V5a1 1 0 0 1 1-1Z" />
        </svg>
      );
    case "trash":
      return (
        <svg {...props}>
          <path d="M3 6h18M8 6V4h8v2M19 6l-1 14H6L5 6M10 11v6M14 11v6" />
        </svg>
      );
    default:
      return (
        <svg {...props}>
          <circle cx="12" cy="12" r="8" />
        </svg>
      );
  }
}

function StudioMark() {
  return (
    <span className="studio-mark" aria-hidden="true">
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none">
        <path
          d="M4.5 5.5 9.5 9h5l5-3.5L18.5 14 12 20 5.5 14 4.5 5.5Z"
          stroke="currentColor"
          strokeWidth="1.9"
          strokeLinejoin="round"
        />
        <path d="M9.5 13h.01M14.5 13h.01" stroke="currentColor" strokeWidth="2.4" strokeLinecap="round" />
      </svg>
    </span>
  );
}

export function Sidebar({
  projects,
  active,
  shell,
  me,
  onSelect,
  onNewProject,
  onSendProject,
  onShareProject,
  onRenameProject,
  onDeleteProject,
  onNewProfile,
  view,
  onView,
  onSettings,
}: {
  projects: Project[];
  active: Project | null;
  shell: Shell;
  me: Me | null;
  onSelect: (p: Project | null) => void;
  onNewProject: (origin: "local" | "team") => void;
  onSendProject: (p: Project) => void;
  onShareProject: (p: Project) => void;
  onRenameProject: (p: Project) => void;
  onDeleteProject: (p: Project) => void;
  view: View;
  onView: (v: View) => void;
  onNewProfile: () => void;
  onSettings: () => void;
  onSupport: () => void;
}) {
  const { t, resolved } = useI18n();
  const [theme, setTheme] = useTheme();
  const isZh = resolved === "zh";
  const local = shell.mode === "local";
  const [menu, setMenu] = useState<string | null>(null);

  const labelFor = (v: View) =>
    v === "suiteLab"
      ? (isZh ? "Suite Lab · 审计" : "Suite Lab")
      : v === "apiCli"
        ? (isZh ? "API & CLI 密钥" : "API & CLI")
        : t(`nav.${v}` as never);

  const toggleTheme = () => {
    const isLight =
      theme === "light" ||
      (theme === "system" && window.matchMedia("(prefers-color-scheme: light)").matches);
    setTheme(isLight ? "dark" : "light");
  };

  return (
    <aside className="sidebar">
      <div className="brand donut-brand">
        <div className="studio-brand-left">
          <StudioMark />
          <div className="studio-brand-text">
            <span className="studio-brand-name">Camoufox</span>
            <span className="studio-brand-sub">Studio</span>
          </div>
        </div>
        <span className="donut-brand-tag">HTTP</span>
      </div>

      <button className="primary newProfile" onClick={onNewProfile}>
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.3" strokeLinecap="round" aria-hidden="true">
          <path d="M12 5v14M5 12h14" />
        </svg>
        <span>{t("bar.newProfile")}</span>
      </button>

      <nav>
        {((local
          ? (["profiles", "suiteLab", "apiCli", "proxies", "extensions", "bookmarks", "trash"] as const)
          : (["profiles", "suiteLab", "apiCli", "sharedWithMe", "proxies", "extensions", "bookmarks", "assistants", "users", "trash"] as const)) as readonly View[]
        ).map((v) => (
          <button
            key={v}
            className={view === v && !(v === "profiles" && active) ? "nav active" : "nav"}
            onClick={() => {
              if (v === "profiles") onSelect(null);
              onView(v);
            }}
          >
            <span className="navLabel">
              <NavIcon view={v} />
              <span>{labelFor(v)}</span>
            </span>
            {v === "suiteLab" && <span className="navPill">LAB</span>}
            {v === "apiCli" && <span className="navPill navPillKey">KEY</span>}
          </button>
        ))}

        {(local
          ? ([["local", "app.projects"]] as const)
          : ([
              ["team", "app.projectsTeam"],
              ["local", "app.projectsHere"],
            ] as const)
        ).map(([side, label]) => (
          <div key={side}>
            <div className="section" style={{ marginTop: "var(--s-4)" }}>
              {t(label as never)}
              <button
                className="linky sectionAdd"
                onClick={() => onNewProject(side)}
                title={t(side === "local" ? "app.newProjectHere" : "app.newProject")}
              >
                +
              </button>
            </div>
            {projects.filter((p) => p.origin === side).length === 0 && (
              <div className="empty">
                {side === "team" ? t("app.nothingShared") : t("app.noFoldersHere")}
              </div>
            )}
            {projects
              .filter((p) => p.origin === side)
              .map((p) => (
                <div key={p.id} className="projectRow">
                  <button
                    className={p.id === active?.id && view === "profiles" ? "nav active" : "nav"}
                    onClick={() => {
                      onSelect(p);
                      onView("profiles");
                    }}
                    onContextMenu={(e) => {
                      e.preventDefault();
                      setMenu(menu === p.id ? null : p.id);
                    }}
                  >
                    <span className="navLabel ellipsis">
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" className="navIcon" aria-hidden="true">
                        <path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V7Z" />
                      </svg>
                      <span className="ellipsis">{p.name}</span>
                    </span>
                    <span className="count">{p.profile_count}</span>
                  </button>
                  {menu === p.id && (
                    <div className="projectMenu">
                      <button
                        className="ghost"
                        onClick={() => {
                          setMenu(null);
                          onRenameProject(p);
                        }}
                      >
                        {t("proj.rename")}
                      </button>
                      {!local && p.origin === "local" && (
                        <button
                          className="ghost"
                          onClick={() => {
                            setMenu(null);
                            onSendProject(p);
                          }}
                        >
                          {t("proj.sendAll")}
                        </button>
                      )}
                      {!local && p.origin === "team" && (
                        <button
                          className="ghost"
                          onClick={() => {
                            setMenu(null);
                            onShareProject(p);
                          }}
                        >
                          {t("proj.shareAll")}
                        </button>
                      )}
                      <button
                        className="ghost"
                        onClick={() => {
                          setMenu(null);
                          onDeleteProject(p);
                        }}
                      >
                        {t("proj.delete")}
                      </button>
                    </div>
                  )}
                </div>
              ))}
          </div>
        ))}
      </nav>

      <div className="foot studio-foot">
        {me && <div className="who ellipsis">{me.email}</div>}
        <div className="studio-status-line" title={shell.server_url ?? "http://127.0.0.1:5274"}>
          <span className="studio-live-dot" aria-hidden="true" />
          <span className="muted small ellipsis">
            {local ? (isZh ? "本地回环服务在线" : "Local HTTP Online") : shell.server_url}
          </span>
        </div>
        <div className="footRow">
          <div className="muted small ellipsis mono" title={shell.machine_name}>
            {shell.machine_name}
          </div>
          <button
            className="iconBtn"
            onClick={toggleTheme}
            title={isZh ? "切换深色/浅色主题" : "Toggle theme"}
            aria-label={isZh ? "切换深色/浅色主题" : "Toggle theme"}
          >
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
              <path d="M12 3a6 6 0 0 0 9 9 9 9 0 1 1-9-9Z" />
            </svg>
          </button>
          <button
            className="iconBtn"
            onClick={onSettings}
            title={t("app.settings")}
            aria-label={t("app.settings")}
          >
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" aria-hidden="true">
              <circle cx="12" cy="12" r="3.2" stroke="currentColor" strokeWidth="1.6" />
              <path
                d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 1 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 1 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.6a1.65 1.65 0 0 0 1-1.51V3a2 2 0 1 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9v0a1.65 1.65 0 0 0 1.51 1H21a2 2 0 1 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"
                stroke="currentColor"
                strokeWidth="1.5"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
            </svg>
          </button>
        </div>
      </div>
    </aside>
  );
}
