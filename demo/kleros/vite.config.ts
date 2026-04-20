import { defineConfig } from 'vite'
import { tanstackStart } from '@tanstack/react-start/plugin/vite'
import tailwindcss from '@tailwindcss/vite'

export default defineConfig({
  define: {
    global: 'globalThis',
  },
  server: {
    port: 3001,
  },
  plugins: [
    tanstackStart({ srcDirectory: 'app' }),
    tailwindcss(),
  ],
})
