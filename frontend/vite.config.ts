import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

// https://vite.dev/config/
export default defineConfig({
  plugins: [vue()],
  build: {
    rollupOptions: {
      output: {
        manualChunks: {
          element: ['element-plus'],
        },
      },
    },
  },
  server: {
      port: 5173,
      proxy: {
        '/api': {
          // Static proxy target: VITE_API_BASE is read at runtime by api/client.ts instead.
          target: 'http://localhost:8000',
          changeOrigin: true,
        },
      },
    },
  }
)
