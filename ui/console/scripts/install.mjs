// Copy the built console into the Python package so `aig console` can serve it without Node.
import { copyFileSync, mkdirSync } from 'node:fs'
const dest = new URL('../../../aig/console_static/', import.meta.url)
mkdirSync(dest, { recursive: true })
copyFileSync(new URL('../dist/index.html', import.meta.url), new URL('index.html', dest))
console.log('installed dist/index.html -> aig/console_static/index.html')
