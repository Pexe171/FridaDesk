import React, { createContext, useContext, useEffect, useState } from 'react';

// Contexto global para estado de UI e preferências
const UIContext = createContext();

export function UIProvider({ children }) {
  const [page, setPage] = useState('dispositivos');
  const [theme, setTheme] = useState(() => localStorage.getItem('theme') || 'light');
  const [hackerMode, setHackerMode] = useState(() => {
    try {
      return JSON.parse(localStorage.getItem('hackerMode')) || false;
    } catch {
      return false;
    }
  });
  const [matrixSpeed, setMatrixSpeed] = useState(() => {
    const v = Number(localStorage.getItem('matrixSpeed'));
    return Number.isFinite(v) ? v : 2;
  });
  const [matrixDensity, setMatrixDensity] = useState(() => {
    const v = Number(localStorage.getItem('matrixDensity'));
    return Number.isFinite(v) ? v : 20;
  });
  const [reducedMotion, setReducedMotion] = useState(false);
  const [primaryColor, setPrimaryColor] = useState(
    () => localStorage.getItem('primaryColor') || '#222222'
  );
  const [accentColor, setAccentColor] = useState(
    () => localStorage.getItem('accentColor') || '#4caf50'
  );

  useEffect(() => {
    localStorage.setItem('theme', theme);
  }, [theme]);

  useEffect(() => {
    localStorage.setItem('hackerMode', JSON.stringify(hackerMode));
  }, [hackerMode]);

  useEffect(() => {
    localStorage.setItem('matrixSpeed', matrixSpeed);
  }, [matrixSpeed]);

  useEffect(() => {
    localStorage.setItem('matrixDensity', matrixDensity);
  }, [matrixDensity]);

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
        hackerMode,
        setHackerMode,
        matrixSpeed,
        setMatrixSpeed,
        matrixDensity,
        setMatrixDensity,
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

