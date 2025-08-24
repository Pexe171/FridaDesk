import React from 'react';
import Titulo from '../components/Titulo.jsx';

export default function Historico() {
  return (
    <div className="content">
      <Titulo>Histórico</Titulo>
      <div className="table-container">
        <table>
          <thead>
            <tr>
              <th>Data</th>
              <th>Dispositivo</th>
              <th>Script</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>01/01/2024</td>
              <td>Device 1</td>
              <td>Script A</td>
              <td>OK</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  );
}
