import { defineConfig } from 'vite'
import { tanstackStart } from '@tanstack/react-start/plugin/vite'
import tailwindcss from '@tailwindcss/vite'

export default defineConfig({
  server: {
    port: 3000,
    strictPort: true,
    allowedHosts: ['zk-eidas.fly.dev', 'zk-eidas.com', 'www.zk-eidas.com'],
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
