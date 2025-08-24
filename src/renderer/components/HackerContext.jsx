import React, { createContext, useContext, useEffect, useState } from 'react';

const HackerContext = createContext();

export function HackerProvider({ children }) {
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
    const media = window.matchMedia('(prefers-reduced-motion: reduce)');
    const update = () => setReducedMotion(media.matches);
    update();
    media.addEventListener('change', update);
    return () => media.removeEventListener('change', update);
  }, []);

  return (
    <HackerContext.Provider
      value={{
        hackerMode,
        setHackerMode,
        matrixSpeed,
        setMatrixSpeed,
        matrixDensity,
        setMatrixDensity,
        reducedMotion,
      }}
    >
      {children}
    </HackerContext.Provider>
  );
}

export function useHacker() {
  return useContext(HackerContext);
}

