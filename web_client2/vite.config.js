import { defineConfig } from 'vite';

export default defineConfig({
  server: {
    port: 3000,
    cors: true,
  },
  build: {
    outDir: 'dist-web',
    sourcemap: true,
  },
  define: {
    global: 'globalThis',
  },
  resolve: {
    alias: {
      buffer: 'buffer',
    },
  },
});
