// SPDX-License-Identifier: AGPL-3.0-or-later
// Adapted from Fury Browser (Copyright 2026 Bogdan Shapovalov and the Fury authors)

import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

const bridgeTarget = process.env.CAMOUFOX_UI_BRIDGE ?? "http://127.0.0.1:5274";

export default defineConfig({
  plugins: [react()],
  server: {
    host: "127.0.0.1",
    port: 5273,
    strictPort: true,
    proxy: {
      "/rpc": {
        target: bridgeTarget,
        changeOrigin: true,
      },
      "/api": {
        target: bridgeTarget,
        changeOrigin: true,
      },
    },
  },
});
