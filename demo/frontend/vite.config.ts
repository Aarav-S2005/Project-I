import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

const gatewayTarget = process.env.GATEWAY_URL || 'http://localhost:8000'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    port: 4000,
    host: true,
    proxy: {
      '/auth': {
        target: gatewayTarget,
        changeOrigin: true,
      },
      '/api': {
        target: gatewayTarget,
        changeOrigin: true,
      },
      '/audit': {
        target: gatewayTarget,
        changeOrigin: true,
      },
      '/health': {
        target: gatewayTarget,
        changeOrigin: true,
      },
    },
  },
  preview: {
    port: 4000,
    host: true,
    proxy: {
      '/auth': {
        target: gatewayTarget,
        changeOrigin: true,
      },
      '/api': {
        target: gatewayTarget,
        changeOrigin: true,
      },
      '/audit': {
        target: gatewayTarget,
        changeOrigin: true,
      },
      '/health': {
        target: gatewayTarget,
        changeOrigin: true,
      },
    },
  },
})
