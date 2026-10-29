/**
 * favicon.ts — URL del icono de un sitio, servida desde el PROPIO backend (no desde Google).
 *
 * Antes cada tarjeta construía `https://www.google.com/s2/favicons?domain=…`, lo que revelaba a
 * Google el dominio de cada cuenta y abría `img-src` a un host externo (canal de exfiltración ante
 * un XSS). Ahora se apunta al proxy `/api/favicon/<dominio>/` (mismo origen, CSP `img-src 'self'`):
 * el servidor descarga el favicon del sitio y lo devuelve cacheado. Si no hay icono, el proxy da
 * 404 y el <img> cae a su fallback vía `onError`.
 */

import { API_BASE_URL } from '../config/api';

/** Normaliza un `website` a su hostname (sin esquema, `www.`, ruta ni puerto). */
function extractDomain(website: string): string {
  return (website || '')
    .trim()
    .replace(/^https?:\/\//i, '')
    .split('/')[0]
    .replace(/^www\./i, '')
    .replace(/:\d+$/, '')
    .toLowerCase();
}

/** URL del proxy de favicon para un `website`. Cadena vacía si no hay dominio utilizable. */
export function getFaviconUrl(website: string): string {
  const domain = extractDomain(website);
  if (!domain) return '';
  return `${API_BASE_URL}/api/favicon/${encodeURIComponent(domain)}/`;
}
