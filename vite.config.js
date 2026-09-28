import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

const apiPort = process.env.SENTINELMESH_API_PORT || '8000';

export default defineConfig({
  plugins: [react()],
  server: {
    host: '127.0.0.1',
    port: 5173,
    strictPort: true,
    proxy: {
      '/api': {
        target: `http://127.0.0.1:${apiPort}`,
        changeOrigin: true,
      },
    },
  },
});
