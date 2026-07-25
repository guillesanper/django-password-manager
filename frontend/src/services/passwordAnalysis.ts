// services/passwordAnalysis.ts — Análisis de seguridad de contraseñas EN CLIENTE (paso 27).
//
// Zero-knowledge: el servidor ya no puede descifrar, así que la entropía, la fortaleza, los
// duplicados y los patrones se calculan aquí, sobre las contraseñas ya descifradas en memoria.
// Portado 1:1 de las funciones puras que vivían en el servidor (security_views v1).
//
// Para HaveIBeenPwned se usa el PROXY k-anonimato del backend (`/api/security/hibp-range/<prefix>/`):
// el navegador calcula SHA-1 de la contraseña y envía SÓLO el prefijo de 5 hex; la comparación del
// sufijo ocurre aquí. Ni la contraseña ni el hash completo salen del cliente. (La CSP
// `connect-src 'self'` impide llamar a HIBP directamente desde el navegador.)
import type { PasswordStrength, BreachInfo } from './securityService';
import { API_BASE_URL } from '../config/api';

const LOWERCASE = 'abcdefghijklmnopqrstuvwxyz';
const UPPERCASE = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const DIGITS = '0123456789';
const SPECIAL = '!@#$%^&*()_+-=[]{}|;:,.<>?';

/** Entropía en bits, con penalizaciones por secuencias, repeticiones y patrones de teclado. */
export function calculatePasswordEntropy(password: string): number {
  if (!password) return 0;

  const chars = new Set(password);
  let charsetSize = 0;
  if ([...chars].some((c) => LOWERCASE.includes(c))) charsetSize += 26;
  if ([...chars].some((c) => UPPERCASE.includes(c))) charsetSize += 26;
  if ([...chars].some((c) => DIGITS.includes(c))) charsetSize += 10;
  if ([...chars].some((c) => SPECIAL.includes(c))) charsetSize += new Set(SPECIAL).size;

  // Caracteres fuera de los sets conocidos: +1 cada uno.
  const known = new Set([...LOWERCASE, ...UPPERCASE, ...DIGITS, ...SPECIAL]);
  for (const c of chars) if (!known.has(c)) charsetSize += 1;

  if (charsetSize === 0) return 0;

  let entropy = password.length * Math.log2(charsetSize);

  // Secuencias (abc, 123, 321)
  let sequencePenalty = 0;
  for (let i = 0; i < password.length - 2; i++) {
    const sub = password.slice(i, i + 3);
    if (
      LOWERCASE.includes(sub.toLowerCase()) ||
      DIGITS.includes(sub) ||
      '9876543210'.includes(sub)
    ) {
      sequencePenalty += 2;
    }
  }

  // Repeticiones
  const counts = new Map<string, number>();
  for (const c of password) counts.set(c, (counts.get(c) || 0) + 1);
  let repetitionPenalty = 0;
  for (const count of counts.values()) if (count > 1) repetitionPenalty += count - 1;

  // Patrones de teclado
  const keyboardPatterns = ['qwerty', 'asdf', 'zxcv', '1234', '4567'];
  let keyboardPenalty = 0;
  const lower = password.toLowerCase();
  for (const pattern of keyboardPatterns) if (lower.includes(pattern)) keyboardPenalty += pattern.length;

  entropy = Math.max(0, entropy - (sequencePenalty + repetitionPenalty + keyboardPenalty));
  return entropy;
}

/** Categoría de fortaleza a partir de la entropía (mismos umbrales que el servidor v1). */
export function getPasswordStrengthCategory(entropy: number): PasswordStrength {
  if (entropy >= 70) return { level: 'very_strong', label: 'Muy Fuerte', color: '#10b981', score: 100 };
  if (entropy >= 50) return { level: 'strong', label: 'Fuerte', color: '#3b82f6', score: 80 };
  if (entropy >= 35) return { level: 'moderate', label: 'Moderada', color: '#f59e0b', score: 60 };
  if (entropy >= 25) return { level: 'weak', label: 'Débil', color: '#f97316', score: 40 };
  return { level: 'very_weak', label: 'Muy Débil', color: '#ef4444', score: 20 };
}

/** Agrupa contraseñas idénticas; devuelve sólo los grupos con más de un miembro (por id). */
export function findDuplicatePasswords(items: { password: string; id: number }[]): Record<string, number[]> {
  const groups: Record<string, number[]> = {};
  for (const item of items) {
    (groups[item.password] ||= []).push(item.id);
  }
  return Object.fromEntries(Object.entries(groups).filter(([, ids]) => ids.length > 1));
}

export interface PatternStats {
  length_distribution: Record<number, number>;
  character_usage: { uppercase: number; lowercase: number; digits: number; special: number };
}

/** Distribución de longitudes y uso de familias de caracteres. */
export function analyzePasswordPatterns(passwords: string[]): PatternStats {
  const stats: PatternStats = {
    length_distribution: {},
    character_usage: { uppercase: 0, lowercase: 0, digits: 0, special: 0 },
  };
  const special = /[!@#$%^&*()_+\-=[\]{}|;:,.<>?]/;
  for (const pwd of passwords) {
    stats.length_distribution[pwd.length] = (stats.length_distribution[pwd.length] || 0) + 1;
    if (/[A-Z]/.test(pwd)) stats.character_usage.uppercase += 1;
    if (/[a-z]/.test(pwd)) stats.character_usage.lowercase += 1;
    if (/\d/.test(pwd)) stats.character_usage.digits += 1;
    if (special.test(pwd)) stats.character_usage.special += 1;
  }
  return stats;
}

async function sha1HexUpper(text: string): Promise<string> {
  const bytes = new TextEncoder().encode(text);
  const digest = await crypto.subtle.digest('SHA-1', bytes);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
    .toUpperCase();
}

/** Consulta un prefijo al proxy k-anonimato del backend; devuelve un mapa sufijo→count. */
async function fetchHibpRange(prefix: string): Promise<Map<string, number>> {
  const res = await fetch(`${API_BASE_URL}/api/security/hibp-range/${prefix}/`, {
    headers: { Accept: 'application/json' },
    credentials: 'include',
  });
  if (!res.ok) throw new Error(`HIBP proxy error ${res.status}`);
  const data = await res.json();
  const map = new Map<string, number>();
  for (const line of String(data.ranges || '').split('\n')) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    const [suffix, count] = trimmed.split(':');
    if (suffix) map.set(suffix.toUpperCase(), parseInt(count, 10) || 0);
  }
  return map;
}

/**
 * Comprueba una lista de contraseñas contra HIBP por k-anonimato. Deduplica por prefijo SHA-1
 * (una petición por prefijo, con concurrencia limitada) y devuelve un mapa contraseña→BreachInfo.
 */
export async function checkPasswordBreaches(passwords: string[]): Promise<Map<string, BreachInfo>> {
  const result = new Map<string, BreachInfo>();
  const unique = Array.from(new Set(passwords));
  if (unique.length === 0) return result;

  const hashes = new Map<string, string>();
  await Promise.all(unique.map(async (p) => hashes.set(p, await sha1HexUpper(p))));

  const prefixes = Array.from(new Set([...hashes.values()].map((h) => h.slice(0, 5))));

  const ranges = new Map<string, Map<string, number> | null>();
  const CONCURRENCY = 6;
  for (let i = 0; i < prefixes.length; i += CONCURRENCY) {
    const chunk = prefixes.slice(i, i + CONCURRENCY);
    await Promise.all(
      chunk.map(async (pref) => {
        try {
          ranges.set(pref, await fetchHibpRange(pref));
        } catch {
          ranges.set(pref, null);
        }
      }),
    );
  }

  for (const p of unique) {
    const hash = hashes.get(p)!;
    const range = ranges.get(hash.slice(0, 5));
    if (!range) {
      result.set(p, {
        is_breached: false,
        breach_count: 0,
        message: 'No se pudo verificar (error del servicio)',
        error: true,
      });
      continue;
    }
    const count = range.get(hash.slice(5)) || 0;
    result.set(
      p,
      count > 0
        ? {
            is_breached: true,
            breach_count: count,
            message: `Esta contraseña aparece ${count} veces en filtraciones de datos conocidas`,
          }
        : { is_breached: false, breach_count: 0, message: 'No se encontró en filtraciones conocidas' },
    );
  }

  return result;
}
