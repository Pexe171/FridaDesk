import React from 'react';

export default function Topbar({ onHistorico }) {
  return (
    <div className="topbar">
      <div className="status">
        <span>ADB: offline</span>
        <span>Frida: offline</span>
      </div>
      <div className="acoes">
        <label>
          Tema
          <input type="checkbox" />
        </label>
        <label>
          Efeitos
          <input type="checkbox" />
        </label>
        <button onClick={onHistorico} className="btn">
          Histórico
        </button>
      </div>
    </div>
  );
}
