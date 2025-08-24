import React from 'react';
import Titulo from '../components/Titulo.jsx';

export default function Scripts() {
  return (
    <div className="content">
      <Titulo>Scripts</Titulo>
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
