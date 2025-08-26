import React, { useState } from 'react';

export default function Tooltip({ label, children }) {
  const [visivel, setVisivel] = useState(false);
  return (
    <div
      className="tooltip-container"
      onMouseEnter={() => setVisivel(true)}
      onMouseLeave={() => setVisivel(false)}
    >
      {children}
      {visivel && <div className="tooltip-bubble">{label}</div>}
    </div>
  );
}
