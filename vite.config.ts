import { defineConfig } from 'vite';

export default defineConfig({
  server: {
    port: 3500,
    host: true,
    strictPort: true,
    open: false,
  },
  test: {
    globals: true,
    environment: 'node',
  },
});
