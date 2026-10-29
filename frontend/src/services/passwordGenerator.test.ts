/**
 * passwordGenerator.test.ts — L3 (vitest / jsdom).
 *
 * Cubre N2 (hallazgo cerrado en el commit 26b4c97) contra el código REAL de passwordGenerator.ts:
 *   - CSPRNG: usa crypto.getRandomValues, NUNCA Math.random (el bug original).
 *   - Rejection sampling: sin sesgo de módulo en cryptoRandomInt y generateFromCharset.
 *   - Fisher-Yates insesgado: generateStrongPassword baraja de verdad (no el .sort() sesgado).
 *
 * Es la red de regresión de que el CSPRNG no se revierte a Math.random.
 */
import { describe, it, expect, vi, afterEach } from 'vitest';
import { cryptoRandomInt, generateFromCharset, generateStrongPassword } from './passwordGenerator';

afterEach(() => {
  vi.restoreAllMocks();
});

// ===========================================================================
// N2 — CSPRNG, no Math.random
// ===========================================================================
describe('N2 — usa CSPRNG (crypto.getRandomValues), nunca Math.random', () => {
  it('generar NO invoca Math.random y SÍ crypto.getRandomValues', () => {
    const mathSpy = vi.spyOn(Math, 'random');
    const cryptoSpy = vi.spyOn(crypto, 'getRandomValues');

    generateStrongPassword(24);
    generateFromCharset('abcdef', 50);
    cryptoRandomInt(1000);

    expect(mathSpy).not.toHaveBeenCalled();
    expect(cryptoSpy).toHaveBeenCalled();
  });
});

// ===========================================================================
// cryptoRandomInt — rango, casos límite y uniformidad (rejection sampling)
// ===========================================================================
describe('cryptoRandomInt — entero uniforme en [0, max)', () => {
  it('maxExclusive <= 1 devuelve 0 (sin llamar al CSPRNG innecesariamente)', () => {
    expect(cryptoRandomInt(1)).toBe(0);
    expect(cryptoRandomInt(0)).toBe(0);
    expect(cryptoRandomInt(-5)).toBe(0);
  });

  it('siempre dentro de [0, max) para varios módulos', () => {
    for (const max of [2, 3, 6, 7, 26, 100]) {
      for (let i = 0; i < 5000; i++) {
        const v = cryptoRandomInt(max);
        expect(v).toBeGreaterThanOrEqual(0);
        expect(v).toBeLessThan(max);
        expect(Number.isInteger(v)).toBe(true);
      }
    }
  });

  it('distribución sensiblemente uniforme (max=6, no divisor de 2^32) — sin sesgo de módulo', () => {
    const max = 6;
    const N = 120000;
    const counts = new Array(max).fill(0);
    for (let i = 0; i < N; i++) counts[cryptoRandomInt(max)]++;
    const expected = N / max;
    for (const c of counts) {
      // ±15% es ~holgado (>15σ): un fallo aquí sería sesgo real, no ruido.
      expect(Math.abs(c - expected) / expected).toBeLessThan(0.15);
    }
  });
});

// ===========================================================================
// generateFromCharset — longitud, alfabeto y uniformidad
// ===========================================================================
describe('generateFromCharset — muestreo uniforme sin sesgo de módulo', () => {
  it('respeta la longitud pedida', () => {
    for (const len of [1, 5, 16, 40, 100]) {
      expect(generateFromCharset('abcdefghijklmnop', len)).toHaveLength(len);
    }
  });

  it('casos límite: charset vacío o longitud no positiva → ""', () => {
    expect(generateFromCharset('', 10)).toBe('');
    expect(generateFromCharset('abc', 0)).toBe('');
    expect(generateFromCharset('abc', -3)).toBe('');
  });

  it('sólo produce caracteres del alfabeto dado', () => {
    const charset = 'ABCXYZ0189';
    const out = generateFromCharset(charset, 3000);
    for (const ch of out) expect(charset).toContain(ch);
  });

  it('uniformidad sobre un alfabeto de 26 (256 % 26 ≠ 0: la cola se rechaza)', () => {
    const charset = 'abcdefghijklmnopqrstuvwxyz';
    // getRandomValues acota a 65 536 bytes/llamada y generateFromCharset dimensiona el buffer a
    // `length`: se acumula en varias tandas por debajo de ese tope para no desbordar la cuota.
    const counts: Record<string, number> = {};
    let total = 0;
    for (let batch = 0; batch < 4; batch++) {
      const out = generateFromCharset(charset, 40000);
      total += out.length;
      for (const ch of out) counts[ch] = (counts[ch] ?? 0) + 1;
    }
    const expected = total / charset.length;
    for (const ch of charset) {
      expect(Math.abs((counts[ch] ?? 0) - expected) / expected).toBeLessThan(0.12);
    }
  });
});

// ===========================================================================
// generateStrongPassword — categorías garantizadas y Fisher-Yates insesgado
// ===========================================================================
describe('generateStrongPassword — categorías + barajado insesgado', () => {
  const hasLower = (s: string) => /[a-z]/.test(s);
  const hasUpper = (s: string) => /[A-Z]/.test(s);
  const hasDigit = (s: string) => /[0-9]/.test(s);
  const hasSymbol = (s: string) => /[!@#$%^&*()_+\-=[\]{}|;:,.<>?]/.test(s);

  it('respeta la longitud', () => {
    for (const len of [4, 8, 16, 32]) {
      expect(generateStrongPassword(len)).toHaveLength(len);
    }
    expect(generateStrongPassword()).toHaveLength(16); // por defecto
  });

  it('con length >= 4 garantiza al menos una de cada categoría', () => {
    for (let i = 0; i < 300; i++) {
      const pw = generateStrongPassword(8);
      expect(hasLower(pw)).toBe(true);
      expect(hasUpper(pw)).toBe(true);
      expect(hasDigit(pw)).toBe(true);
      expect(hasSymbol(pw)).toBe(true);
    }
  });

  it('con length < 4 no puede garantizar categorías: muestrea del alfabeto completo', () => {
    const pw = generateStrongPassword(3);
    expect(pw).toHaveLength(3);
  });

  it('Fisher-Yates real: la posición 0 NO es siempre minúscula (sin barajar lo sería)', () => {
    // El generador construye [lower, upper, digit, symbol, ...relleno] y baraja. Sin barajado la
    // posición 0 sería SIEMPRE minúscula. Con un Fisher-Yates insesgado, la fracción es una
    // proporción intermedia. Cota holgada para que nunca sea flaky, pero que caza el "no barajó".
    const N = 800;
    let startsLower = 0;
    for (let i = 0; i < N; i++) {
      if (/[a-z]/.test(generateStrongPassword(16)[0])) startsLower++;
    }
    const frac = startsLower / N;
    expect(frac).toBeGreaterThan(0.05); // aparece
    expect(frac).toBeLessThan(0.85); // pero NO siempre → hubo barajado
  });
});
