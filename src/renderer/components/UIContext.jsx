import React, { createContext, useContext, useEffect, useState } from 'react';

// Contexto global para estado de UI e preferências
const UIContext = createContext();

export function UIProvider({ children }) {
  const [page, setPage] = useState('dispositivos');
  const [theme, setTheme] = useState(() => localStorage.getItem('theme') || 'dark');
  const [reducedMotion, setReducedMotion] = useState(false);
  const [primaryColor, setPrimaryColor] = useState(
    () => localStorage.getItem('primaryColor') || '#222222'
  );
  const [accentColor, setAccentColor] = useState(
    () => localStorage.getItem('accentColor') || '#4caf50'
  );

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('theme', theme);
  }, [theme]);

  useEffect(() => {
    document.documentElement.style.setProperty('--primary-color', primaryColor);
    localStorage.setItem('primaryColor', primaryColor);
  }, [primaryColor]);

  useEffect(() => {
    document.documentElement.style.setProperty('--accent-color', accentColor);
    localStorage.setItem('accentColor', accentColor);
  }, [accentColor]);

  useEffect(() => {
    const media = window.matchMedia('(prefers-reduced-motion: reduce)');
    const update = () => setReducedMotion(media.matches);
    update();
    media.addEventListener('change', update);
    return () => media.removeEventListener('change', update);
  }, []);

  return (
    <UIContext.Provider
      value={{
        page,
        setPage,
        theme,
        setTheme,
        reducedMotion,
        primaryColor,
        setPrimaryColor,
        accentColor,
        setAccentColor,
      }}
    >
      {children}
    </UIContext.Provider>
  );
}

export function useUI() {
  return useContext(UIContext);
}

