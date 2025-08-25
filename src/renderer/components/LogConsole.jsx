import React, { useEffect, useRef, useState } from 'react';

export default function LogConsole({ logs, onClear }) {
  const [paused, setPaused] = useState(false);
  const [filters, setFilters] = useState({ send: true, error: true, event: true });
  const [search, setSearch] = useState('');
  const [rate, setRate] = useState(0);
  const containerRef = useRef(null);
  const lastCountRef = useRef(0);

  useEffect(() => {
    if (!paused && containerRef.current) {
      containerRef.current.scrollTop = containerRef.current.scrollHeight;
    }
  }, [logs, paused]);

  useEffect(() => {
    const interval = setInterval(() => {
      const count = logs.length;
      setRate(count - lastCountRef.current);
      lastCountRef.current = count;
    }, 1000);
    return () => clearInterval(interval);
  }, [logs]);

  const filtered = logs.filter(
    (l) => filters[l.type] && l.message.toLowerCase().includes(search.toLowerCase())
  );

  const highlight = (text) => {
    if (!search) return text;
    const regex = new RegExp(`(${search})`, 'gi');
    return text.split(regex).map((part, i) =>
      part.toLowerCase() === search.toLowerCase() ? <mark key={i}>{part}</mark> : part
    );
  };

  const copyAll = () => {
    navigator.clipboard.writeText(filtered.map((l) => l.message).join('\n'));
  };

  const copyLine = (line) => navigator.clipboard.writeText(line);

  return (
    <div>
      <div className="log-console-toolbar">
        <label>
          <input
            type="checkbox"
            checked={filters.send}
            onChange={(e) => setFilters({ ...filters, send: e.target.checked })}
          />{' '}
          send
        </label>
        <label>
          <input
            type="checkbox"
            checked={filters.error}
            onChange={(e) => setFilters({ ...filters, error: e.target.checked })}
          />{' '}
          error
        </label>
        <label>
          <input
            type="checkbox"
            checked={filters.event}
            onChange={(e) => setFilters({ ...filters, event: e.target.checked })}
          />{' '}
          event
        </label>
        <input
          placeholder="Buscar..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
        <button onClick={() => setPaused((p) => !p)} className="btn">
          {paused ? 'CONTINUAR' : 'PAUSAR'}
        </button>
        <button onClick={copyAll} className="btn">
          Copiar tudo
        </button>
        <button onClick={onClear} className="btn btn-ghost">
          Limpar
        </button>
        <span>{rate} msg/s</span>
      </div>
      <div ref={containerRef} className="log-console-content card">
        {filtered.map((l, i) => (
          <div key={i} className="log-line">
            <span>{highlight(l.message)}</span>
            <button onClick={() => copyLine(l.message)} className="btn btn-ghost">
              Copiar
            </button>
          </div>
        ))}
      </div>
    </div>
  );
}

