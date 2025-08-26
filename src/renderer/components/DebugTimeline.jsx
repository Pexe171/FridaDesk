// Autor: Pexe (instagram: @David.devloli)
import React from 'react';

export default function DebugTimeline({ events }) {
  return (
    <div className="card">
      <ul className="timeline">
        {events.map((e, i) => (
          <li key={i} className="timeline-item">
            <span className="time">
              {new Date(e.ts).toLocaleTimeString()}
            </span>
            <span className="type">{e.type}</span>
            {e.description && <span className="msg">{e.description}</span>}
            {!e.description && e.message && (
              <span className="msg">{e.message}</span>
            )}
            {e.reason && <span className="msg">{e.reason}</span>}
          </li>
        ))}
      </ul>
    </div>
  );
}

