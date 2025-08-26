import React, { useEffect, useState } from 'react';
import { useUI } from './UIContext';

export default function Topbar({ onHistorico }) {
  const [adbOnline, setAdbOnline] = useState(false);
  const [fridaOnline, setFridaOnline] = useState(false);
  const { theme, setTheme } = useUI();

  useEffect(() => {
    const check = async () => {
      const devices = await window.myAPI.listDevices().catch(() => []);
      setAdbOnline(devices.length > 0);
      if (devices.length > 0) {
        const frida = await window.myAPI
          .isFridaRunning(devices[0].id)
          .catch(() => false);
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
          <select value={theme} onChange={(e) => setTheme(e.target.value)}>
            <option value="dark">Escuro</option>
            <option value="light">Claro</option>
            <option value="contrast">Alto contraste</option>
          </select>
        </label>
        <label>
          Efeitos
          <input type="checkbox" />
        </label>
        <button onClick={onHistorico} className="btn btn-ghost">
          Histórico
        </button>
      </div>
    </div>
  );
}
