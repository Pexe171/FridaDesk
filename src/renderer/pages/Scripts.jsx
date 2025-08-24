import React from 'react';

export default function Scripts() {
  return (
    <div className="content">
      <h2>Scripts</h2>
      <div>
        <input type="file" />
        <textarea rows={4} placeholder="Cole o código aqui"></textarea>
      </div>
      <h3>Favoritos</h3>
      <ul>
        <li>Script exemplo <span>tags: frida, teste</span></li>
      </ul>
    </div>
  );
}
