// SPDX-License-Identifier: AGPL-3.0-or-later
// UI design pattern selectively absorbed from Donut Browser (bandwidth-sparkline.tsx)
// Lightweight dependency-free SVG area sparkline with subtle baseline grid & terminal marker.

import type { SuiteTrafficBucket } from "../../api";

export function BandwidthSparkline({
  data,
  gradientId = "donut-sparkline-grad",
  height = 36,
}: {
  data: SuiteTrafficBucket[];
  gradientId?: string;
  height?: number;
}) {
  const width = 180;
  const padX = 3;
  const padY = 4;
  const values = data.length > 1 ? data.map((d) => Math.max(0, d.bandwidth)) : [0, 0];
  const hasTraffic = values.some((v) => v > 0);
  const max = Math.max(1, ...values);
  const stepX = (width - padX * 2) / Math.max(1, values.length - 1);

  const points = values.map((v, idx) => {
    const x = padX + idx * stepX;
    const y = hasTraffic
      ? height - padY - (v / max) * (height - padY * 2)
      : height - padY - 1;
    return [x, y] as const;
  });

  const linePath = points
    .map(([x, y], idx) => `${idx === 0 ? "M" : "L"}${x.toFixed(1)},${y.toFixed(1)}`)
    .join(" ");

  const areaPath =
    `${linePath} L${points[points.length - 1][0].toFixed(1)},${(height - padY).toFixed(1)} ` +
    `L${points[0][0].toFixed(1)},${(height - padY).toFixed(1)} Z`;

  const last = points[points.length - 1];

  return (
    <svg
      className="donut-sparkline"
      viewBox={`0 0 ${width} ${height}`}
      preserveAspectRatio="none"
      aria-hidden="true"
      style={{ width: "100%", height }}
    >
      <defs>
        <linearGradient id={gradientId} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor="var(--donut-chart-1)" stopOpacity="0.48" />
          <stop offset="100%" stopColor="var(--donut-chart-1)" stopOpacity="0.02" />
        </linearGradient>
      </defs>
      <line
        x1={padX}
        y1={(height / 2).toFixed(1)}
        x2={width - padX}
        y2={(height / 2).toFixed(1)}
        stroke="var(--line)"
        strokeDasharray="2 3"
        strokeWidth="0.8"
      />
      <path d={areaPath} fill={`url(#${gradientId})`} />
      <path
        d={linePath}
        fill="none"
        stroke="var(--donut-chart-1)"
        strokeWidth="1.75"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      <circle
        cx={last[0].toFixed(1)}
        cy={last[1].toFixed(1)}
        r="2.4"
        fill="var(--donut-chart-1)"
      />
    </svg>
  );
}
