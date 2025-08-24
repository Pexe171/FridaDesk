import React, { useEffect, useRef } from 'react';
import { useUI } from './UIContext.jsx';

export default function MatrixRain() {
  const canvasRef = useRef(null);
  const { hackerMode, matrixSpeed, matrixDensity, reducedMotion } = useUI();

  useEffect(() => {
    if (!hackerMode || reducedMotion) return;
    const canvas = canvasRef.current;
    const ctx = canvas.getContext('2d');
    let width = (canvas.width = window.innerWidth);
    let height = (canvas.height = window.innerHeight);
    const fontSize = Math.max(1, matrixDensity);
    const columns = Math.max(1, Math.floor(width / fontSize));
    const drops = Array(columns).fill(0);

    const draw = () => {
      ctx.fillStyle = 'rgba(0, 0, 0, 0.05)';
      ctx.fillRect(0, 0, width, height);
      ctx.fillStyle = '#0f0';
      ctx.font = `${fontSize}px monospace`;
      drops.forEach((y, i) => {
        const text = String.fromCharCode(0x30a0 + Math.random() * 96);
        const x = i * fontSize;
        ctx.fillText(text, x, y);
        if (y > height && Math.random() > 0.975) drops[i] = 0;
        else drops[i] = y + matrixSpeed;
      });
      frame = requestAnimationFrame(draw);
    };
    let frame = requestAnimationFrame(draw);

    const onResize = () => {
      width = canvas.width = window.innerWidth;
      height = canvas.height = window.innerHeight;
    };
    window.addEventListener('resize', onResize);

    return () => {
      cancelAnimationFrame(frame);
      window.removeEventListener('resize', onResize);
      ctx.clearRect(0, 0, width, height);
    };
  }, [hackerMode, matrixSpeed, matrixDensity, reducedMotion]);

  if (!hackerMode) return null;
  return <canvas ref={canvasRef} className="matrix-canvas" aria-hidden="true" />;
}

