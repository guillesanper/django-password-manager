import { defineConfig } from 'vitest/config';

// Config L3 del plan de pruebas (§2, §5.1). Corre el núcleo zero-knowledge del cliente
// (crypto.ts + passwordGenerator.ts) con vitest sobre jsdom en Node.
//
// PUNTO CIEGO declarado (PLAN-DE-PRUEBAS.md §8, trampa Z14): Node/jsdom es MÁS permisivo que
// el navegador con AES-GCM sin additionalData. Estos tests verifican corrección funcional y la
// FORMA del código; la regresión real del bug del 25-jul es L4/navegador.
export default defineConfig({
  test: {
    environment: 'jsdom',
    include: ['src/services/**/*.test.ts'],
    // hash-wasm (Argon2id) corre en WASM: dale margen a la derivación KDF (m=64 MiB, t=3).
    testTimeout: 20000,
    coverage: {
      provider: 'v8',
      // §5.1: cobertura ≥90% del núcleo cripto del cliente. Se mide SOLO sobre estos dos
      // módulos; el resto de la SPA (React/DOM) no es objeto de L3.
      include: ['src/services/crypto.ts', 'src/services/passwordGenerator.ts'],
      reporter: ['text', 'text-summary'],
      thresholds: {
        // El objetivo del plan es ≥90%. No se pone fail-under aquí para no romper la primera
        // pasada de medición (§5.1: "primera pasada mide"); el objetivo se afirma en el informe.
      },
    },
  },
});
