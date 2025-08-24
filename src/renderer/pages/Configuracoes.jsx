import React from 'react';
import Titulo from '../components/Titulo.jsx';
import { useUI } from '../components/UIContext.jsx';

export default function Configuracoes() {
  const {
    hackerMode,
    setHackerMode,
    matrixSpeed,
    setMatrixSpeed,
    matrixDensity,
    setMatrixDensity,
    primaryColor,
    setPrimaryColor,
    accentColor,
    setAccentColor,
  } = useUI();

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
              onChange={(e) => setPrimaryColor(e.target.value)}
              style={{ marginLeft: '0.5rem' }}
            />
          </label>
          <label style={{ display: 'block' }}>
            Cor de destaque
            <input
              type="color"
              value={accentColor}
              onChange={(e) => setAccentColor(e.target.value)}
              style={{ marginLeft: '0.5rem' }}
            />
          </label>
        </div>
        <div style={{ border: '1px solid #ccc', padding: '1rem', flex: '1 1 200px' }}>
          <h3>Ferramentas</h3>
          <input placeholder="ex.: /usr/bin/adb" />
          <input placeholder="ex.: /usr/bin/frida-server" />
        </div>
        <div style={{ border: '1px solid #ccc', padding: '1rem', flex: '1 1 200px' }}>
          <h3>Modo Hacker</h3>
          <label style={{ display: 'block', marginBottom: '0.5rem' }}>
            <input
              type="checkbox"
              checked={hackerMode}
              onChange={(e) => setHackerMode(e.target.checked)}
            />{' '}
            Ativar
          </label>
          {hackerMode && (
            <>
              <label style={{ display: 'block' }}>
                Densidade
                <input
                  type="number"
                  min="10"
                  max="50"
                  value={matrixDensity}
                  onChange={(e) => setMatrixDensity(Number(e.target.value))}
                />
              </label>
              <label style={{ display: 'block' }}>
                Velocidade
                <input
                  type="number"
                  min="1"
                  max="20"
                  value={matrixSpeed}
                  onChange={(e) => setMatrixSpeed(Number(e.target.value))}
                />
              </label>
            </>
          )}
        </div>
      </div>
    </div>
  );
}

