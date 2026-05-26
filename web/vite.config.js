import { defineConfig } from 'vite';
import wasm from 'vite-plugin-wasm';

export default defineConfig({
  plugins: [wasm()],
  server: {
    port: 3001,
    cors: true,
    fs: {
      // pir-sdk-wasm/pkg lives outside web/. `--target web` wasm bundles
      // fetch their .wasm at runtime via /@fs/<absolute-path>/..., which
      // Vite 8 blocks by default. Allow the repo root so dev can resolve
      // the sibling workspace package.
      allow: ['..'],
    },
  },
  build: {
    outDir: 'dist-web',
    sourcemap: true,
    rollupOptions: {
      input: {
        // Main PIR client app.
        main: 'index.html',
        // Reproducibility recipe page — self-contained, explains how
        // to verify the SEV-SNP MEASUREMENT pin against the chip-signed
        // value via sev-snp-measure + bpir-admin attest.
        reproduce: 'reproduce.html',
        // Anonymous rate-limiting demo (ARC + Cashu) — self-contained,
        // talks only to the dev-issuer (free issuance + co-located gate).
        'ratelimit-demo': 'ratelimit-demo.html',
      },
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
