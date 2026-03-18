/**
 * Browser polyfills for Node.js modules
 */

// Buffer polyfill
import { Buffer } from 'buffer';
if (typeof window !== 'undefined') {
  (window as any).Buffer = Buffer;
}

// Process polyfill
if (typeof window !== 'undefined') {
  const processPolyfill = {
    browser: true,
    env: {},
    version: 'v18.0.0',
    nextTick: (fn: (...args: any[]) => void, ...args: any[]) => setTimeout(() => fn(...args), 0),
    cwd: () => '/',
    platform: 'browser',
  };
  
  // @ts-ignore
  window.process = window.process || processPolyfill;
  
  // Also set on globalThis for modules that access it via global
  // @ts-ignore
  globalThis.process = globalThis.process || processPolyfill;
}