// SPDX-License-Identifier: AGPL-3.0-or-later
// Adapted from Fury Browser (Copyright 2026 Bogdan Shapovalov and the Fury authors)

import { useI18n } from "../i18n";

export function Brand({ version }: { version?: string }) {
  const { t } = useI18n();
  return (
    <>
      <h1>Camoufox Studio</h1>
      {version && <p className="loginVersion">{t("auth.version", { version })}</p>}
    </>
  );
}
