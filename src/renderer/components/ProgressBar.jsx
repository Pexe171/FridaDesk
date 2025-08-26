import React from 'react';

export default function ProgressBar({ value = 0, max = 100 }) {
  const percent = Math.min(100, Math.round((value / max) * 100));
  return (
    <div className="progress-bar">
      <div className="progress-bar-inner" style={{ width: `${percent}%` }} />
    </div>
  );
}
