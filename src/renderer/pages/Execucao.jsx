import React, { useEffect, useRef, useState } from 'react';
import Titulo from '../components/Titulo.jsx';
import LogConsole from '../components/LogConsole.jsx';
import DebugTimeline from '../components/DebugTimeline.jsx';

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
  const [timeline, setTimeline] = useState([]);
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
    const ts = Date.now();
    setTimeline((t) => [...t, { ts, type: 'start' }]);
    intervalRef.current = setInterval(() => {
      const types = ['send', 'error', 'event'];
      const type = types[Math.floor(Math.random() * types.length)];
      const now = Date.now();
      const message = `${type} message ${now}`;
      setLogs((l) => [...l, { type, message }]);
      setTimeline((t) => [...t, { ts: now, type, message }]);
    }, 500);
  };

  const stop = () => {
    setRunning(false);
    clearInterval(intervalRef.current);
    intervalRef.current = null;
    setTimeline((t) => [...t, { ts: Date.now(), type: 'stop' }]);
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
      <div
        className="card"
        style={{
          display: 'flex',
          flexWrap: 'wrap',
          gap: 'var(--espaco-sm)',
          marginBottom: 'var(--espaco-md)',
        }}
      >
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
          <div
            style={{ display: 'flex', gap: 'var(--espaco-xs)', flexWrap: 'wrap' }}
          >
            {filteredProcesses.map((p) => (
              <button
                key={p}
                type="button"
                onClick={() => addProcess(p)}
                className="btn btn-ghost"
              >
                {p}
              </button>
            ))}
          </div>
          <div
            style={{
              display: 'flex',
              gap: 'var(--espaco-xs)',
              flexWrap: 'wrap',
              marginTop: 'var(--espaco-xs)',
            }}
          >
            {selectedProcesses.map((p) => (
              <span key={p} className="chip">
                {p}
                <button
                  type="button"
                  onClick={() => removeProcess(p)}
                  className="btn btn-ghost"
                >
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

        <label
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 'var(--espaco-xs)',
          }}
        >
          <input
            type="checkbox"
            checked={spawn}
            onChange={(e) => setSpawn(e.target.checked)}
          />
          Spawn
        </label>

        <button onClick={start} disabled={running} className="btn btn-primary">
          Rodar
        </button>
        <button onClick={stop} disabled={!running} className="btn btn-ghost">
          Parar
        </button>
      </div>
      <LogConsole logs={logs} onClear={() => setLogs([])} />
      <DebugTimeline events={timeline} />
    </div>
  );
}
