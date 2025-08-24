import React from 'react';

export default function Execucao() {
  return (
    <div className="content">
      <h2>Execução</h2>
      <div>
        <select>
          <option>Device 1</option>
        </select>
        <select>
          <option>Processo 1</option>
        </select>
        <select>
          <option>Script 1</option>
        </select>
        <button>Iniciar</button>
      </div>
      <div className="logs" style={{ border: '1px solid #ccc', padding: '1rem', height: '200px', overflowY: 'auto' }}>
        <p>Logs aparecerão aqui...</p>
      </div>
    </div>
  );
}
