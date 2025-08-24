import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App.jsx';
import './styles.css';
import { HackerProvider } from './components/HackerContext.jsx';

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <HackerProvider>
      <App />
    </HackerProvider>
  </React.StrictMode>
);
