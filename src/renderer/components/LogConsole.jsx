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
      <div
        style={{
          display: 'flex',
          flexWrap: 'wrap',
          gap: '0.5rem',
          marginBottom: '0.5rem',
          alignItems: 'center',
        }}
      >
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
        <button onClick={() => setPaused((p) => !p)}>
          {paused ? 'CONTINUAR' : 'PAUSAR'}
        </button>
        <button onClick={copyAll}>Copiar tudo</button>
        <button onClick={onClear}>Limpar</button>
        <span>{rate} msg/s</span>
      </div>
      <div
        ref={containerRef}
        style={{ border: '1px solid #ccc', padding: '1rem', height: '200px', overflowY: 'auto' }}
      >
        {filtered.map((l, i) => (
          <div key={i} style={{ display: 'flex', justifyContent: 'space-between', gap: '0.5rem' }}>
            <span>{highlight(l.message)}</span>
            <button onClick={() => copyLine(l.message)}>Copiar</button>
          </div>
        ))}
      </div>
    </div>
  );
}

