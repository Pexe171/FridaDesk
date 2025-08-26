import React from 'react';

export default function DataChart({ data = [] }) {
  const width = 200;
  const height = 100;
  if (data.length === 0) {
    return <svg className="data-chart" width={width} height={height}></svg>;
  }
  const max = Math.max(...data);
  const points = data
    .map((v, i) => `${(i / (data.length - 1)) * width},${height - (v / max) * height}`)
    .join(' ');
  return (
    <svg className="data-chart" width={width} height={height}>
      <polyline points={points} fill="none" stroke="var(--cor-primaria)" strokeWidth="2" />
    </svg>
  );
}
