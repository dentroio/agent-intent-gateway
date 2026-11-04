import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { viteSingleFile } from 'vite-plugin-singlefile'

// One self-contained HTML file: served by `aig console`, or published with an embedded snapshot.
export default defineConfig({
  plugins: [react(), viteSingleFile()],
  base: './',
  build: { outDir: 'dist', assetsInlineLimit: 100_000_000, cssCodeSplit: false },
})
