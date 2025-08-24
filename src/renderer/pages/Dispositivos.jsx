import React from 'react';
import { useToast } from '../components/ToastContext.jsx';
import Titulo from '../components/Titulo.jsx';

export default function Dispositivos() {
  const toast = useToast();

  const handleConnect = () => {
    toast('carregando', 'Conectando...');
    setTimeout(() => toast('sucesso', 'Conectado!'), 1000);
  };

  return (
    <div className="content">
      <Titulo>Dispositivos</Titulo>
      <div>
        <input placeholder="IP" />
        <input placeholder="Porta" />
        <button onClick={handleConnect}>Conectar</button>
      </div>
      <div className="table-container">
        <table>
          <thead>
            <tr>
              <th>Nome</th>
              <th>IP</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>Dispositivo 1</td>
              <td>127.0.0.1</td>
              <td>Offline</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  );
}
