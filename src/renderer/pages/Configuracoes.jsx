import React from 'react';

export default function Configuracoes() {
  return (
    <div className="content">
      <h2>Configurações</h2>
      <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap' }}>
        <div style={{ border: '1px solid #ccc', padding: '1rem', flex: '1 1 200px' }}>
          <h3>Tema</h3>
          <button>Claro</button>
          <button>Escuro</button>
        </div>
        <div style={{ border: '1px solid #ccc', padding: '1rem', flex: '1 1 200px' }}>
          <h3>Ferramentas</h3>
          <input placeholder="Caminho do ADB" />
          <input placeholder="Caminho do Frida" />
        </div>
      </div>
    </div>
  );
}
