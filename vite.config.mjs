import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { resolve } from 'node:path';

export default defineConfig({
  root: resolve('primordial/core/web/frontend'),
  publicDir: false,
  plugins: [react()],
  build: {
    outDir: resolve('primordial/core/web/static'),
    emptyOutDir: true,
    assetsDir: 'assets',
  },
});
