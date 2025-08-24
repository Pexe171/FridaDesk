import React, { useState } from 'react';
import Titulo from '../components/Titulo.jsx';

export default function Historico() {
  const data = [
    { date: '2024-01-01', device: 'Device 1', script: 'Script A', status: 'OK' },
    { date: '2024-01-02', device: 'Device 2', script: 'Script B', status: 'Erro' },
  ];

  const [deviceFilter, setDeviceFilter] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [dateFilter, setDateFilter] = useState('');

  const filtered = data.filter(
    (d) =>
      (!deviceFilter || d.device === deviceFilter) &&
      (!statusFilter || d.status === statusFilter) &&
      (!dateFilter || d.date === dateFilter)
  );

  const exportJSONL = () => {
    const content = filtered.map((d) => JSON.stringify(d)).join('\n');
    const blob = new Blob([content], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'historico.jsonl';
    a.click();
  };

  const exportTXT = () => {
    const content = filtered
      .map((d) => `${d.date}\t${d.device}\t${d.script}\t${d.status}`)
      .join('\n');
    const blob = new Blob([content], { type: 'text/plain' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'historico.txt';
    a.click();
  };

  return (
    <div className="content">
      <Titulo>Histórico</Titulo>
      <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap', marginBottom: '0.5rem' }}>
        <select value={deviceFilter} onChange={(e) => setDeviceFilter(e.target.value)}>
          <option value="">Todos dispositivos</option>
          {[...new Set(data.map((d) => d.device))].map((d) => (
            <option key={d}>{d}</option>
          ))}
        </select>
        <select value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)}>
          <option value="">Todos status</option>
          {[...new Set(data.map((d) => d.status))].map((s) => (
            <option key={s}>{s}</option>
          ))}
        </select>
        <input type="date" value={dateFilter} onChange={(e) => setDateFilter(e.target.value)} />
        <button onClick={exportJSONL}>Exportar JSONL</button>
        <button onClick={exportTXT}>Exportar TXT</button>
      </div>
      <div className="table-container">
        <table>
          <thead>
            <tr>
              <th>Data</th>
              <th>Dispositivo</th>
              <th>Script</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((d, i) => (
              <tr key={i}>
                <td>{d.date.split('-').reverse().join('/')}</td>
                <td>{d.device}</td>
                <td>{d.script}</td>
                <td>{d.status}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
