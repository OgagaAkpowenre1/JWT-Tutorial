import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    host: true,
    allowedHosts: [
      '5173-ogagaakpowe-jwttutorial-hthm5276jta.ws-eu118.gitpod.io'
    ]
  }
})
