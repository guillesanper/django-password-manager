/**
 * authService.test.ts — L3 (vitest / jsdom). Cierre de sesión contra un servidor falso.
 *
 * Corre el authService REAL con un `fetch` falso que contesta a `/auth/logout/` con la secuencia
 * de respuestas de cada caso. Las cookies de sesión son HttpOnly: el cliente no puede borrarlas,
 * así que sólo el 200 del servidor cierra la sesión de verdad.
 *
 * Cubre:
 *   N10 — el cliente no da la sesión por cerrada si el servidor no lo confirma. Antes un 429 o
 *         un error de red se tragaban con console.warn, un 503 ({success:false}) ni siquiera
 *         lanzaba, y en todos los casos se emitía 'auth:logout': la UI mostraba el login con
 *         las cookies vivas. Ahora reintenta y, si no hay confirmación, devuelve success:false
 *         sin emitir el evento. La VaultKey sale de memoria en cualquier caso.
 *
 * La mitad de servidor de N10 (el logout no se limita ni depende de Redis ni del access) la
 * cubre `backend/myapp/tests/test_cierre_de_sesion.py` (L1).
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { authService } from './authService';
import { cryptoSession } from './cryptoSession';
import { generateVaultKey, importVaultKey } from './crypto';

const json = (data: unknown, status = 200): Response =>
  new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json' } });

const OK = () => json({ success: true, message: 'Sesión cerrada exitosamente' });
// Lo que respondía el limitador antes de N10 y lo que responde cualquier control que falla cerrado.
const RATE_LIMITED = () => json({ error: 'Demasiados intentos', retry_after: 300 }, 429);
const UNAVAILABLE = () => json({ success: false, code: 'SERVICE_UNAVAILABLE' }, 503);
const NETWORK_DOWN = () => Promise.reject(new TypeError('Failed to fetch'));

/** `fetch` falso: cada POST a /auth/logout/ consume la siguiente respuesta; la última se repite. */
function fakeLogoutServer(...responses: Array<() => Response | Promise<Response>>) {
  const calls: string[] = [];
  const fetch = async (input: RequestInfo | URL, init: RequestInit = {}): Promise<Response> => {
    const path = new URL(String(input), 'http://localhost').pathname;
    calls.push(`${init.method ?? 'GET'} ${path}`);
    if (path !== '/auth/logout/') return json({ error: 'No encontrado' }, 404);
    const respond = responses[Math.min(calls.length - 1, responses.length - 1)];
    return respond();
  };
  return { fetch, calls };
}

const USER = {
  id: 7,
  username: 'ana',
  email: 'ana@example.test',
  firstName: 'Ana',
  lastName: 'Pérez',
  isAuthenticated: true,
  hasMasterKey: true,
};

/** Ejecuta el logout dejando correr las esperas entre reintentos. */
async function logoutWithRetries() {
  const result = authService.logout();
  await vi.runAllTimersAsync();
  return result;
}

let logoutEvents = 0;
const onLogout = () => {
  logoutEvents++;
};

beforeEach(async () => {
  vi.useFakeTimers();
  vi.spyOn(console, 'warn').mockImplementation(() => {});
  // Con la cookie CSRF presente, authService no pide /api/csrf/ antes del POST.
  document.cookie = 'csrftoken=token-csrf-de-prueba';
  localStorage.setItem('user_data', JSON.stringify(USER));
  cryptoSession.unlock(await importVaultKey(generateVaultKey()), USER.id);
  logoutEvents = 0;
  window.addEventListener('auth:logout', onLogout);
});

afterEach(() => {
  window.removeEventListener('auth:logout', onLogout);
  cryptoSession.lock();
  localStorage.clear();
  vi.useRealTimers();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe('N10 — el logout sólo se da por hecho si el servidor lo confirma', () => {
  it('con confirmación, cierra la sesión y emite auth:logout una vez', async () => {
    vi.stubGlobal('fetch', fakeLogoutServer(OK).fetch);

    const result = await logoutWithRetries();

    expect(result).toEqual({ success: true });
    expect(logoutEvents).toBe(1);
    expect(authService.getCurrentUser()).toBeNull();
    expect(cryptoSession.isUnlocked()).toBe(false);
  });

  it('reintenta tras un fallo puntual y cierra cuando el servidor confirma', async () => {
    const server = fakeLogoutServer(UNAVAILABLE, NETWORK_DOWN, OK);
    vi.stubGlobal('fetch', server.fetch);

    const result = await logoutWithRetries();

    expect(server.calls).toEqual(Array(3).fill('POST /auth/logout/'));
    expect(result).toEqual({ success: true });
    expect(logoutEvents).toBe(1);
  });

  it.each([
    ['429 del limitador', RATE_LIMITED],
    ['503 de un control que falla cerrado', UNAVAILABLE],
    ['red caída', NETWORK_DOWN],
  ])('sin confirmación (%s) no da la sesión por cerrada', async (_caso, respuesta) => {
    const server = fakeLogoutServer(respuesta);
    vi.stubGlobal('fetch', server.fetch);

    const result = await logoutWithRetries();

    expect(server.calls).toHaveLength(3);
    expect(result.success).toBe(false);
    expect(result.error).toMatch(/no se pudo cerrar la sesión/i);
    expect(logoutEvents).toBe(0);
    expect(authService.getCurrentUser()).toEqual(USER);
  });

  it('borra la VaultKey de memoria aunque el servidor no confirme', async () => {
    vi.stubGlobal('fetch', fakeLogoutServer(NETWORK_DOWN).fetch);

    await logoutWithRetries();

    expect(cryptoSession.isUnlocked()).toBe(false);
  });
});
