import React from 'react';
import { useCatalog } from './ScriptCatalogContext.jsx';

export default function ScriptTable({ onView }) {
  const {
    filteredScripts,
    search,
    setSearch,
    tagFilter,
    setTagFilter,
    deleteScript,
    toggleFavorite,
  } = useCatalog();

  return (
    <div className="script-table">
      <div className="filters">
        <input
          placeholder="Buscar por nome"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
        <input
          placeholder="Filtrar por tag"
          value={tagFilter}
          onChange={(e) => setTagFilter(e.target.value)}
        />
      </div>
      <table>
        <thead>
          <tr>
            <th>Nome</th>
            <th>Tags</th>
            <th>Ações</th>
          </tr>
        </thead>
        <tbody>
          {filteredScripts.map((s) => (
            <tr key={s.id}>
              <td>{s.name}</td>
              <td>{s.tags.join(', ')}</td>
              <td>
                <button onClick={() => onView(s.id)}>Ver</button>
                <button onClick={() => deleteScript(s.id)}>Excluir</button>
                <button onClick={() => toggleFavorite(s.id)}>
                  {s.favorite ? '★' : '☆'}
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

