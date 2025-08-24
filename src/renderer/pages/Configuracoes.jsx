import React from 'react';
import Titulo from '../components/Titulo.jsx';
import { useHacker } from '../components/HackerContext.jsx';

export default function Configuracoes() {
  const {
    hackerMode,
    setHackerMode,
    matrixSpeed,
    setMatrixSpeed,
    matrixDensity,
    setMatrixDensity,
  } = useHacker();

  return (
    <div className="content">
      <Titulo>Configurações</Titulo>
      <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap' }}>
        <div style={{ border: '1px solid #ccc', padding: '1rem', flex: '1 1 200px' }}>
          <h3>Tema</h3>
          <button>Claro</button>
          <button>Escuro</button>
        </div>
        <div style={{ border: '1px solid #ccc', padding: '1rem', flex: '1 1 200px' }}>
          <h3>Ferramentas</h3>
          <input placeholder="Caminho do ADB" />
          <input placeholder="Caminho do Frida" />
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
