import React, { useState, useEffect, useRef } from 'react';
import Sidebar from './components/Sidebar.jsx';
import Topbar from './components/Topbar.jsx';
import Dispositivos from './pages/Dispositivos.jsx';
import Scripts from './pages/Scripts.jsx';
import Execucao from './pages/Execucao.jsx';
import Historico from './pages/Historico.jsx';
import Configuracoes from './pages/Configuracoes.jsx';
import { ToastProvider } from './components/ToastContext.jsx';

export default function App() {
  const [pagina, setPagina] = useState('dispositivos');
  const inicio = useRef(performance.now());

  const mudarPagina = (p) => {
    inicio.current = performance.now();
    setPagina(p);
  };

  useEffect(() => {
    const duracao = performance.now() - inicio.current;
    console.log(`Tempo de carregamento de ${pagina}: ${duracao.toFixed(2)}ms`);
  }, [pagina]);

  const renderizar = () => {
    switch (pagina) {
      case 'dispositivos':
        return <Dispositivos />;
      case 'scripts':
        return <Scripts />;
      case 'execucao':
        return <Execucao />;
      case 'historico':
        return <Historico />;
      case 'config':
        return <Configuracoes />;
      default:
        return null;
    }
  };

  return (
    <ToastProvider>
      <div className="app-grid">
        <Sidebar current={pagina} onChange={mudarPagina} />
        <div className="main">
          <Topbar onHistorico={() => mudarPagina('historico')} />
          {renderizar()}
        </div>
      </div>
    </ToastProvider>
  );
}
