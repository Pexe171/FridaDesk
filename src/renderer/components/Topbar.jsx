import React, { useEffect, useState } from 'react';
import { listDevices } from '../../adbService.js';
import { isFridaRunning } from '../../fridaService.js';

export default function Topbar({ onHistorico }) {
  const [adbOnline, setAdbOnline] = useState(false);
  const [fridaOnline, setFridaOnline] = useState(false);

  useEffect(() => {
    const check = async () => {
      const devices = await listDevices().catch(() => []);
      setAdbOnline(devices.length > 0);
      if (devices.length > 0) {
        const frida = await isFridaRunning(devices[0].id).catch(() => false);
        setFridaOnline(frida);
      } else {
        setFridaOnline(false);
      }
    };
    check();
    const id = setInterval(check, 5000);
    return () => clearInterval(id);
  }, []);

  return (
    <div className="topbar">
      <div className="status">
        <span>ADB: {adbOnline ? 'online' : 'offline'}</span>
        <span>Frida: {fridaOnline ? 'online' : 'offline'}</span>
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
