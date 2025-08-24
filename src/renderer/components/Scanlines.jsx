import React from 'react';
import { useHacker } from './HackerContext.jsx';

export default function Scanlines() {
  const { hackerMode } = useHacker();
  if (!hackerMode) return null;
  return <div className="scanlines" aria-hidden="true" />;
}

