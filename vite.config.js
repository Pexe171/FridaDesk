import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  base: './',
  plugins: [react()],
  // Externaliza módulos nativos do Node e adbkit para o ambiente Electron
  build: {
    rollupOptions: {
      external: [
        'adbkit',
        'assert',
        'child_process',
        'crypto',
        'events',
        'fs',
        'net',
        'path',
        'stream',
      ],
    },
  },
});
