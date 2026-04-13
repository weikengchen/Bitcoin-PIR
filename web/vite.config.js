import { defineConfig } from 'vite';
import wasm from 'vite-plugin-wasm';

export default defineConfig({
  plugins: [wasm()],
  server: {
    port: 3001,
    cors: true,
  },
  build: {
    outDir: 'dist-web',
    sourcemap: true,
    rollupOptions: {
      // pir-sdk-wasm is optional - externalize so build succeeds without it
      // The sdk-bridge.ts handles the runtime import failure gracefully
      external: ['pir-sdk-wasm'],
    },
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
