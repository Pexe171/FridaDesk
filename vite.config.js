import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  base: './',
  plugins: [react()],
  optimizeDeps: {
    exclude: ['adbkit', 'adbkit-logcat', 'adbkit-monkey', 'frida'],
  },
  // Externaliza módulos nativos do Node e bibliotecas do adbkit para o ambiente Electron
  build: {
    rollupOptions: {
      external: [
        'adbkit',
        'adbkit-logcat',
        'adbkit-monkey',
        'frida',
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
