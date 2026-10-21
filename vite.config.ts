import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig(({ command, mode }) => {
  if (command === 'build' && mode === 'emulator') {
    throw new Error('Emulator mode cannot be built for deployment. Use pnpm build.')
  }
  return {
  plugins: [react()],
  build: {
    chunkSizeWarningLimit: 650,
    rollupOptions: {
      output: {
        manualChunks: {
          firebase: ['firebase/app', 'firebase/auth', 'firebase/firestore', 'firebase/storage', 'firebase/functions'],
        },
      },
    },
  },
  }
});
