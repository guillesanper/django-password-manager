import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react-swc'
import tailwindcss from '@tailwindcss/vite'
import path from 'path'

export default defineConfig({
  plugins: [
    react(),
    tailwindcss(),
  ],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  build: {
    // Debe coincidir con DJANGO_VITE_ASSETS_PATH (backend/static/dist) y quedar
    // dentro del contexto de build de Docker, que es `backend/`. Apuntando a
    // `../static/dist` los assets caían en la raíz del repo: ni Django los
    // encontraba ni llegaban a la imagen.
    outDir: '../backend/static/dist',
    // Nombre explícito, no `true`: Vite 5+ escribiría `.vite/manifest.json`, y
    // `collectstatic` ignora por defecto todo lo que empieza por punto ('.*'),
    // así que el manifest nunca llegaría a STATIC_ROOT, que es donde lo busca
    // django-vite.
    manifest: 'manifest.json',
    emptyOutDir: true,
    rollupOptions: {
      input: {
        // Entry points para cada página de tu app
        main: './src/main.tsx',
      },
      output: {
        entryFileNames: '[name]-[hash].js',
        chunkFileNames: '[name]-[hash].js',
        assetFileNames: '[name]-[hash].[ext]'
      }
    }
  },
  server: {
    host: 'localhost',
    port: 5174,
    cors: true,
    hmr: {
      port: 5174
    }
  }
})