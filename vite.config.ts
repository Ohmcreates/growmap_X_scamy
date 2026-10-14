import { defineConfig } from 'vite';

export default defineConfig({
  server: {
    port: 3500,
    host: true,
    strictPort: true,
    open: false,
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:5001',
        changeOrigin: true,
      },
      '/predict': {
        target: 'http://127.0.0.1:5001',
        changeOrigin: true,
      },
    },
  },
  test: {
    globals: true,
    environment: 'node',
  },
});
