import React, { useEffect, useRef } from 'react';
import { useHacker } from './HackerContext.jsx';

export default function Titulo({ children }) {
  const { hackerMode, reducedMotion } = useHacker();
  const ref = useRef(null);

  useEffect(() => {
    if (!hackerMode || reducedMotion) return;
    let active = true;
    let timeout;
    const glitch = () => {
      if (!ref.current) return;
      ref.current.classList.add('glitch-text');
      setTimeout(() => ref.current && ref.current.classList.remove('glitch-text'), 150);
      const delay = 3000 + Math.random() * 4000;
      if (active) timeout = setTimeout(glitch, delay);
    };
    glitch();
    return () => {
      active = false;
      clearTimeout(timeout);
      ref.current && ref.current.classList.remove('glitch-text');
    };
  }, [hackerMode, reducedMotion]);

  return <h2 ref={ref}>{children}</h2>;
}

