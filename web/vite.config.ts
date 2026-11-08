import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// Dev server proxies /api to the ASP.NET Core API (backend/src/Shield.Api, port 5080).
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: { '/api': 'http://localhost:5080' },
  },
})
