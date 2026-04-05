import { defineConfig } from 'vite'
import { tanstackStart } from '@tanstack/react-start/plugin/vite'
import tailwindcss from '@tailwindcss/vite'
import path from 'path'

export default defineConfig({
  define: {
    global: 'globalThis',
  },
  resolve: {
    alias: {
      'zk-eidas-wasm': path.resolve(__dirname, 'pkg/zk-eidas-wasm.js'),
      buffer: 'buffer/',
      crypto: path.resolve(__dirname, 'app/lib/crypto-shim.ts'),
    },
  },
  preview: {
    port: 3000,
    strictPort: true,
    allowedHosts: ['eidas-longfellow.fly.dev', 'zk-eidas.fly.dev', 'zk-eidas.com', 'www.zk-eidas.com'],
  },
  server: {
    port: 3000,
    strictPort: true,
    allowedHosts: ['eidas-longfellow.fly.dev', 'zk-eidas.fly.dev', 'zk-eidas.com', 'www.zk-eidas.com'],
    fs: {
      allow: ['../..'],
    },
  },
  esbuild: {
    jsx: 'automatic',
  },
  worker: {
    format: 'es',
  },
  plugins: [
    tanstackStart({
      srcDirectory: 'app',
    }),
    tailwindcss(),
  ],
})
