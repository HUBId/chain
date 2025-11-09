import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

const base = process.env.ASSET_BASE_PATH || '/';

export default defineConfig({
  base,
  plugins: [react()],
  build: {
    sourcemap: true,
  },
  server: {
    port: 5173,
  },
});
