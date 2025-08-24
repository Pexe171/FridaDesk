import React, { useState } from 'react';
import Titulo from '../components/Titulo.jsx';
import ImportForm from '../components/ImportForm.jsx';
import ScriptTable from '../components/ScriptTable.jsx';
import ScriptEditor from '../components/ScriptEditor.jsx';
import { useCatalog } from '../components/ScriptCatalogContext.jsx';

export default function Scripts() {
  const { scripts, updateScript } = useCatalog();
  const [currentId, setCurrentId] = useState(null);

  const current = scripts.find((s) => s.id === currentId);

  const handleChange = (code) => {
    if (current) {
      updateScript(current.id, { code });
    }
  };

  return (
    <div className="content">
      <Titulo>Scripts</Titulo>
      <ImportForm />
      <ScriptTable onView={setCurrentId} />
      {current && (
        <ScriptEditor code={current.code} onChange={handleChange} />
      )}
    </div>
  );
}

