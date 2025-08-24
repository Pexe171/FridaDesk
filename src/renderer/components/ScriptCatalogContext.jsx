import React, { createContext, useContext, useState } from 'react';

const ScriptCatalogContext = createContext();

const exemplos = [
  {
    id: 1,
    name: 'Script exemplo',
    code: "// exemplo\nconsole.log('oi');",
    tags: ['frida', 'teste'],
    favorite: false,
  },
];

export function ScriptCatalogProvider({ children }) {
  const [scripts, setScripts] = useState(exemplos);
  const [search, setSearch] = useState('');
  const [tagFilter, setTagFilter] = useState('');

  const addScript = (script) => {
    setScripts((prev) => [
      ...prev,
      { ...script, id: Date.now(), favorite: false },
    ]);
  };

  const deleteScript = (id) => {
    setScripts((prev) => prev.filter((s) => s.id !== id));
  };

  const toggleFavorite = (id) => {
    setScripts((prev) =>
      prev.map((s) =>
        s.id === id ? { ...s, favorite: !s.favorite } : s
      )
    );
  };

  const updateScript = (id, data) => {
    setScripts((prev) =>
      prev.map((s) => (s.id === id ? { ...s, ...data } : s))
    );
  };

  const filteredScripts = scripts.filter((s) => {
    const matchTag = tagFilter ? s.tags.includes(tagFilter) : true;
    const matchSearch = s.name.toLowerCase().includes(search.toLowerCase());
    return matchTag && matchSearch;
  });

  return (
    <ScriptCatalogContext.Provider
      value={{
        scripts,
        addScript,
        deleteScript,
        toggleFavorite,
        updateScript,
        search,
        setSearch,
        tagFilter,
        setTagFilter,
        filteredScripts,
      }}
    >
      {children}
    </ScriptCatalogContext.Provider>
  );
}

export function useCatalog() {
  return useContext(ScriptCatalogContext);
}

