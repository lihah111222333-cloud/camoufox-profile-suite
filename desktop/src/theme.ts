// SPDX-License-Identifier: AGPL-3.0-or-later
// Adapted from Fury Browser (Copyright 2026 Bogdan Shapovalov and the Fury authors)

import { useEffect, useState } from "react";

export const themes = ["system", "dark", "light"] as const;
export type Theme = (typeof themes)[number];

const KEY = "fury.theme";

export function useTheme(): [Theme, (t: Theme) => void] {
  const [theme, setStored] = useState<Theme>(
    () => (localStorage.getItem(KEY) as Theme) || "dark",
  );

  useEffect(() => {
    const root = document.documentElement;
    const media = window.matchMedia("(prefers-color-scheme: light)");

    const apply = () => {
      const resolved = theme === "system" ? (media.matches ? "light" : "dark") : theme;
      root.setAttribute("data-theme", resolved);
    };
    apply();

    if (theme !== "system") return;
    media.addEventListener("change", apply);
    return () => media.removeEventListener("change", apply);
  }, [theme]);

  return [
    theme,
    (t: Theme) => {
      localStorage.setItem(KEY, t);
      setStored(t);
    },
  ];
}
