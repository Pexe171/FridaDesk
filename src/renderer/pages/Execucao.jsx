import React from 'react';
import Titulo from '../components/Titulo.jsx';

export default function Execucao() {
  return (
    <div className="content">
      <Titulo>Execução</Titulo>
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
