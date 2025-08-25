// Autor: Pexe (instagram: @David.devloli)
import React, { useState, useEffect, useCallback } from 'react';
import { useToast } from '../components/ToastContext.jsx';
import Titulo from '../components/Titulo.jsx';

export default function Dispositivos() {
  const toast = useToast();
  const [devices, setDevices] = useState([]);
  const [ip, setIp] = useState('');
  const [port, setPort] = useState('');
  const [modelFilter, setModelFilter] = useState('');
  const [serialFilter, setSerialFilter] = useState('');

  const refreshDevices = useCallback(async () => {
    const list = await window.myAPI.listDevices().catch(() => []);
    setDevices(list);
    console.log('Dispositivos recebidos:', list);
  }, []);

  useEffect(() => {
    refreshDevices();
    console.log('Iniciando refresh de dispositivos...');
    const interval = setInterval(refreshDevices, 5000);
    return () => clearInterval(interval);
  }, [refreshDevices]);

  const handleConnect = async () => {
    toast('carregando', 'Conectando...');
    try {
      await window.myAPI.connectAdb(ip, Number(port) || 5555);
      toast('sucesso', 'Conectado!');
      refreshDevices();
    } catch (e) {
      toast('erro', 'Falha ao conectar');
    }
  };

  const filtered = devices.filter(
    (d) =>
      d.model.toLowerCase().includes(modelFilter.toLowerCase()) &&
      d.id.toLowerCase().includes(serialFilter.toLowerCase())
  );

  return (
    <div className="content">
      <Titulo>Dispositivos</Titulo>
      <div
        className="card"
        style={{
          display: 'flex',
          gap: 'var(--espaco-sm)',
          marginBottom: 'var(--espaco-md)',
          flexWrap: 'wrap',
        }}
      >
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
        <button onClick={handleConnect} className="btn btn-primary">
          Conectar ADB (TCP/IP)
        </button>
      </div>

      <div
        className="card"
        style={{
          display: 'flex',
          gap: 'var(--espaco-sm)',
          marginBottom: 'var(--espaco-sm)',
          flexWrap: 'wrap',
        }}
      >
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
        <table className="tabela">
          <thead>
            <tr>
              <th>Modelo</th>
              <th>Serial</th>
              <th>Status</th>
              <th>Ações</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((d) => {
              const status =
                d.type === 'offline'
                  ? 'offline'
                  : d.type === 'emulator'
                  ? 'emulador'
                  : 'online';
              const cls = status === 'offline' ? 'offline' : 'online';
              return (
                <tr key={d.id}>
                  <td>{d.model}</td>
                  <td>{d.id}</td>
                  <td>
                    <span className={`status-halo ${cls}`}></span>
                    {status}
                  </td>
                  <td>
                    <button
                      className="btn btn-primary"
                      onClick={async () => {
                        toast('carregando', 'Inicializando Frida...');
                        try {
                          await window.myAPI.ensureFrida(d.id);
                          toast('sucesso', 'Frida iniciado');
                        } catch {
                          toast('erro', 'Falha no Frida');
                        }
                      }}
                    >
                      Frida
                    </button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
