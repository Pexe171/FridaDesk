import React, { useState } from 'react';
import MonacoEditor from '@monaco-editor/react';
import prettier from 'prettier/standalone';
import parserBabel from 'prettier/parser-babel';

export default function ScriptEditor({ code, onChange }) {
  const [pos, setPos] = useState({ line: 1, column: 1 });

  const beautify = () => {
    try {
      const formatted = prettier.format(code, {
        parser: 'babel',
        plugins: [parserBabel],
      });
      onChange(formatted);
    } catch (e) {
      console.error(e);
    }
  };

  const handleMount = (editor) => {
    editor.onDidChangeCursorPosition((e) => {
      setPos({ line: e.position.lineNumber, column: e.position.column });
    });
  };

  return (
    <div className="script-editor">
      <MonacoEditor
        height="200px"
        defaultLanguage="javascript"
        value={code}
        onChange={(v) => onChange(v ?? '')}
        onMount={handleMount}
      />
      <div className="editor-bar">
        <button onClick={beautify}>Beautify</button>
        <span>
          L{pos.line}:C{pos.column} ({code.length}b)
        </span>
      </div>
    </div>
  );
}

