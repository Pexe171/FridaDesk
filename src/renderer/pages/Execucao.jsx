import React, { useEffect, useRef, useState } from 'react';
import Titulo from '../components/Titulo.jsx';
import LogConsole from '../components/LogConsole.jsx';

export default function Execucao() {
  const devices = ['Device 1', 'Device 2'];
  const processes = ['app1', 'app2', 'app3'];
  const scripts = ['Script A', 'Script B'];

  const [device, setDevice] = useState(devices[0]);
  const [processQuery, setProcessQuery] = useState('');
  const [selectedProcesses, setSelectedProcesses] = useState([]);
  const [scriptMode, setScriptMode] = useState('catalog');
  const [script, setScript] = useState(scripts[0]);
  const [inlineScript, setInlineScript] = useState('');
  const [spawn, setSpawn] = useState(false);
  const [running, setRunning] = useState(false);
  const [logs, setLogs] = useState([]);
  const intervalRef = useRef(null);

  const addProcess = (p) => {
    if (!selectedProcesses.includes(p)) {
      setSelectedProcesses([...selectedProcesses, p]);
    }
    setProcessQuery('');
  };

  const removeProcess = (p) => {
    setSelectedProcesses(selectedProcesses.filter((x) => x !== p));
  };

  const start = () => {
    setRunning(true);
    intervalRef.current = setInterval(() => {
      const types = ['send', 'error', 'event'];
      const type = types[Math.floor(Math.random() * types.length)];
      setLogs((l) => [...l, { type, message: `${type} message ${Date.now()}` }]);
    }, 500);
  };

  const stop = () => {
    setRunning(false);
    clearInterval(intervalRef.current);
    intervalRef.current = null;
  };

  useEffect(() => {
    return () => {
      if (intervalRef.current) clearInterval(intervalRef.current);
    };
  }, []);

  const filteredProcesses = processes.filter((p) =>
    p.toLowerCase().includes(processQuery.toLowerCase())
  );

  return (
    <div className="content">
      <Titulo>Execução</Titulo>
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem', marginBottom: '1rem' }}>
        <select value={device} onChange={(e) => setDevice(e.target.value)}>
          {devices.map((d) => (
            <option key={d}>{d}</option>
          ))}
        </select>

        <div>
          <input
            placeholder="Buscar processo"
            value={processQuery}
            onChange={(e) => setProcessQuery(e.target.value)}
          />
          <div style={{ display: 'flex', gap: '0.25rem', flexWrap: 'wrap' }}>
            {filteredProcesses.map((p) => (
              <button key={p} type="button" onClick={() => addProcess(p)}>
                {p}
              </button>
            ))}
          </div>
          <div style={{ display: 'flex', gap: '0.25rem', flexWrap: 'wrap', marginTop: '0.25rem' }}>
            {selectedProcesses.map((p) => (
              <span
                key={p}
                style={{
                  padding: '0.25rem 0.5rem',
                  background: '#eee',
                  borderRadius: '16px',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.25rem',
                }}
              >
                {p}
                <button type="button" onClick={() => removeProcess(p)}>
                  x
                </button>
              </span>
            ))}
          </div>
        </div>

        <div>
          <label>
            <input
              type="radio"
              name="scriptMode"
              value="catalog"
              checked={scriptMode === 'catalog'}
              onChange={(e) => setScriptMode(e.target.value)}
            />
            Catálogo
          </label>
          <label>
            <input
              type="radio"
              name="scriptMode"
              value="inline"
              checked={scriptMode === 'inline'}
              onChange={(e) => setScriptMode(e.target.value)}
            />
            Inline
          </label>
          {scriptMode === 'catalog' ? (
            <select value={script} onChange={(e) => setScript(e.target.value)}>
              {scripts.map((s) => (
                <option key={s}>{s}</option>
              ))}
            </select>
          ) : (
            <textarea
              placeholder="Código inline"
              value={inlineScript}
              onChange={(e) => setInlineScript(e.target.value)}
              rows={4}
              cols={40}
            />
          )}
        </div>

        <label style={{ display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
          <input
            type="checkbox"
            checked={spawn}
            onChange={(e) => setSpawn(e.target.checked)}
          />
          Spawn
        </label>

        <button onClick={start} disabled={running}>
          Rodar
        </button>
        <button onClick={stop} disabled={!running}>
          Parar
        </button>
      </div>
      <LogConsole logs={logs} onClear={() => setLogs([])} />
    </div>
  );
}
