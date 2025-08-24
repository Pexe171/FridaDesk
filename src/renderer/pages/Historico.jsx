import React from 'react';

export default function Historico() {
  return (
    <div className="content">
      <h2>Histórico</h2>
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
