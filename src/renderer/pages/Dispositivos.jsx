import React, { useState } from 'react';
import { useToast } from '../components/ToastContext.jsx';
import Titulo from '../components/Titulo.jsx';

export default function Dispositivos() {
  const toast = useToast();
  const devices = [
    { model: 'Pixel 5', serial: 'ABC123', status: 'online' },
    { model: 'Galaxy S10', serial: 'XYZ456', status: 'offline' },
  ];
  const [ip, setIp] = useState('');
  const [port, setPort] = useState('');
  const [modelFilter, setModelFilter] = useState('');
  const [serialFilter, setSerialFilter] = useState('');

  const handleConnect = () => {
    toast('carregando', 'Conectando...');
    setTimeout(() => toast('sucesso', 'Conectado!'), 1000);
  };

  const filtered = devices.filter(
    (d) =>
      d.model.toLowerCase().includes(modelFilter.toLowerCase()) &&
      d.serial.toLowerCase().includes(serialFilter.toLowerCase())
  );

  return (
    <div className="content">
      <Titulo>Dispositivos</Titulo>
      <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '1rem' }}>
        <input
          placeholder="IP"
          value={ip}
          onChange={(e) => setIp(e.target.value)}
        />
        <input
          placeholder="Porta"
          value={port}
          onChange={(e) => setPort(e.target.value)}
        />
        <button onClick={handleConnect}>Conectar ADB (TCP/IP)</button>
      </div>

      <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '0.5rem' }}>
        <input
          placeholder="Filtrar por modelo"
          value={modelFilter}
          onChange={(e) => setModelFilter(e.target.value)}
        />
        <input
          placeholder="Filtrar por serial"
          value={serialFilter}
          onChange={(e) => setSerialFilter(e.target.value)}
        />
      </div>

      <div className="table-container">
        <table>
          <thead>
            <tr>
              <th>Modelo</th>
              <th>Serial</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((d) => (
              <tr key={d.serial}>
                <td>{d.model}</td>
                <td>{d.serial}</td>
                <td>
                  <span className={`status-halo ${d.status}`}></span>
                  {d.status}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
