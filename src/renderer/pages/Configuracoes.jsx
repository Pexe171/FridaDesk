import React, { useEffect, useState } from 'react';
import Titulo from '../components/Titulo.jsx';
import { useUI } from '../components/UIContext.jsx';

export default function Configuracoes() {
  const { primaryColor, setPrimaryColor, accentColor, setAccentColor } = useUI();
  const [adbPath, setAdbPath] = useState('');
  const [fridaPath, setFridaPath] = useState('');

  useEffect(() => {
    window.myAPI.getConfig().then((res) => {
      const cfg = res.config || {};
      if (cfg.primaryColor) setPrimaryColor(cfg.primaryColor);
      if (cfg.accentColor) setAccentColor(cfg.accentColor);
      setAdbPath(cfg.adbPath || '');
      setFridaPath(cfg.fridaPath || '');
    });
  }, [setPrimaryColor, setAccentColor]);

  const handlePrimary = (e) => {
    const value = e.target.value;
    setPrimaryColor(value);
    window.myAPI.setConfig('primaryColor', value);
  };

  const handleAccent = (e) => {
    const value = e.target.value;
    setAccentColor(value);
    window.myAPI.setConfig('accentColor', value);
  };

  const handleAdb = (e) => {
    const value = e.target.value;
    setAdbPath(value);
    window.myAPI.setConfig('adbPath', value);
  };

  const handleFrida = (e) => {
    const value = e.target.value;
    setFridaPath(value);
    window.myAPI.setConfig('fridaPath', value);
  };

  return (
    <div className="content">
      <Titulo>Configurações</Titulo>
      <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap' }}>
        <div style={{ border: '1px solid #ccc', padding: '1rem', flex: '1 1 200px' }}>
          <h3>Tema</h3>
          <label style={{ display: 'block', marginBottom: '0.5rem' }}>
            Cor primária
            <input
              type="color"
              value={primaryColor}
              onChange={handlePrimary}
              style={{ marginLeft: '0.5rem' }}
            />
          </label>
          <label style={{ display: 'block' }}>
            Cor de destaque
            <input
              type="color"
              value={accentColor}
              onChange={handleAccent}
              style={{ marginLeft: '0.5rem' }}
            />
          </label>
        </div>
        <div style={{ border: '1px solid #ccc', padding: '1rem', flex: '1 1 200px' }}>
          <h3>Ferramentas</h3>
          <input
            placeholder="ex.: /usr/bin/adb"
            value={adbPath}
            onChange={handleAdb}
          />
          <input
            placeholder="ex.: /usr/bin/frida-server"
            value={fridaPath}
            onChange={handleFrida}
          />
        </div>

      </div>
    </div>
  );
}

