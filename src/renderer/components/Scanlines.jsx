import React from 'react';
import { useUI } from './UIContext.jsx';

export default function Scanlines() {
  const { hackerMode } = useUI();
  if (!hackerMode) return null;
  return <div className="scanlines" aria-hidden="true" />;
}

