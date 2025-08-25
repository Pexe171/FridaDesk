import React from 'react';

const menus = [
  { key: 'dispositivos', label: 'Dispositivos' },
  { key: 'scripts', label: 'Scripts' },
  { key: 'execucao', label: 'Execução' },
  { key: 'historico', label: 'Histórico' },
  { key: 'config', label: 'Configurações' },
];

export default function Sidebar({ current, onChange }) {
  return (
    <aside className="sidebar">
      <div className="brand">FridaDesk</div>
      <nav>
        {menus.map((m) => (
          <button
            key={m.key}
            className={`btn btn-ghost ${current === m.key ? 'active' : ''}`}
            onClick={() => onChange(m.key)}
          >
            <span>{m.label}</span>
          </button>
        ))}
      </nav>
    </aside>
  );
}
