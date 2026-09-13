import tailwindcss from '@tailwindcss/vite';
import react from '@vitejs/plugin-react';
import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vite';
const rootDir = fileURLToPath(new URL('.', import.meta.url));
export default defineConfig({plugins:[react(),tailwindcss()],resolve:{alias:{'@':rootDir}},server:{hmr:process.env.DISABLE_HMR!=='true',watch:process.env.DISABLE_HMR==='true'?null:{}}});
