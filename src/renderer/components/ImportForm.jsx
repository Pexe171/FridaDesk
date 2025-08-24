import React, { useState } from 'react';
import { useCatalog } from './ScriptCatalogContext.jsx';

export default function ImportForm() {
  const { addScript } = useCatalog();
  const [name, setName] = useState('');
  const [tags, setTags] = useState('');
  const [code, setCode] = useState('');
  const [error, setError] = useState('');

  const handleFile = async (e) => {
    const file = e.target.files[0];
    if (file) {
      const text = await file.text();
      setCode(text);
    }
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    if (!name.trim()) {
      setError('Nome é obrigatório');
      return;
    }
    addScript({
      name,
      tags: tags.split(',').map((t) => t.trim()).filter(Boolean),
      code,
    });
    setName('');
    setTags('');
    setCode('');
    setError('');
  };

  return (
    <form onSubmit={handleSubmit} className="import-form">
      <label>
        Nome*
        <input
          value={name}
          onChange={(e) => setName(e.target.value)}
          aria-required="true"
        />
      </label>
      <label>
        Tags
        <input
          value={tags}
          onChange={(e) => setTags(e.target.value)}
          placeholder="separadas por vírgula"
        />
      </label>
      <label>
        Arquivo
        <input type="file" onChange={handleFile} />
      </label>
      <label>
        Código
        <textarea
          rows={4}
          value={code}
          onChange={(e) => setCode(e.target.value)}
          placeholder="Cole o código aqui"
        />
      </label>
      {error && (
        <div role="alert" className="erro">
          {error}
        </div>
      )}
      <button type="submit">Importar</button>
    </form>
  );
}

