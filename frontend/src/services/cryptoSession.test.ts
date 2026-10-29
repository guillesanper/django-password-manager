/**
 * cryptoSession.test.ts — L3 (vitest / jsdom). Elección de clave al cifrar para una bóveda y
 * autobloqueo.
 *
 * crypto.test.ts prueba las primitivas; aquí se prueba qué clave elige cryptoSession para cada
 * bóveda, y que vaultService y passwordService la alimentan y la respetan.
 *
 * Cubre:
 *   N9 — al CIFRAR para una bóveda privada sin su subclave, cryptoSession caía a la VaultKey
 *        principal. Nada fallaba: una sesión que sólo conocía la maestra guardaba "en la bóveda
 *        privada" entradas que sólo protegía la maestra. Ahora lanza, y también si no se sabe
 *        si la bóveda es privada (fail-closed). Al DESCIFRAR se mantiene la caída a la
 *        principal: ahí es segura, porque el tag de AES-GCM falla con la clave equivocada.
 *
 *   N13 — el autobloqueo por inactividad sólo se evaluaba cuando algo llamaba a isUnlocked():
 *        una pestaña abierta con contraseñas en pantalla no se bloqueaba nunca. Ahora hay un
 *        reloj de 30 s y `visibilitychange`, y teclear, hacer clic o hacer scroll renueva el plazo.
 *
 * La otra mitad de N9, que el servidor ata el desbloqueo a la sesión, la cubre
 * `backend/myapp/tests/test_boveda_privada.py` (L1).
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { CryptoSession, cryptoSession, type EntryPayload } from './cryptoSession';
import { generateVaultKey, importVaultKey } from './crypto';
import { vaultService } from './vaultService';
import { passwordService } from './passwordService';

const USER_ID = 7;
const PRIVATE_VAULT = 1;
const PUBLIC_VAULT = 2;
const CLIENT_ID = '0b6e8f3c-5d1a-4c2e-9f7b-2a4d6c8e0f13';
const PAYLOAD: EntryPayload = { website: 'example.org', username: 'ana', password: 'Primera$Clave1' };

const newKey = () => importVaultKey(generateVaultKey());

async function unlockedSession(): Promise<CryptoSession> {
  const session = new CryptoSession();
  session.unlock(await newKey(), USER_ID);
  session.setVaultPrivacy(PRIVATE_VAULT, true);
  session.setVaultPrivacy(PUBLIC_VAULT, false);
  return session;
}

// ===========================================================================
// N9 — la clave para cifrar no se adivina
// ===========================================================================
describe('N9 — cifrar para una bóveda privada exige su subclave', () => {
  it('privada sin subclave → lanza VAULT_LOCKED en vez de usar la clave principal', async () => {
    const session = await unlockedSession();

    await expect(session.encryptEntryForVault(CLIENT_ID, PAYLOAD, PRIVATE_VAULT)).rejects.toMatchObject({
      code: 'VAULT_LOCKED',
    });
  });

  it('privacidad desconocida → lanza (fail-closed)', async () => {
    const session = await unlockedSession();

    await expect(session.encryptEntryForVault(CLIENT_ID, PAYLOAD, 99)).rejects.toMatchObject({
      code: 'VAULT_LOCKED',
    });
  });

  it('pública o sin bóveda → clave principal', async () => {
    const session = await unlockedSession();

    for (const vaultId of [PUBLIC_VAULT, null]) {
      const blob = await session.encryptEntryForVault(CLIENT_ID, PAYLOAD, vaultId);
      await expect(session.decryptEntryForVault(CLIENT_ID, blob, 2, null)).resolves.toEqual(PAYLOAD);
    }
  });

  it('privada con subclave → la subclave, no la principal', async () => {
    const session = await unlockedSession();
    session.unlockVaultKey(PRIVATE_VAULT, await newKey());

    const blob = await session.encryptEntryForVault(CLIENT_ID, PAYLOAD, PRIVATE_VAULT);

    await expect(session.decryptEntryForVault(CLIENT_ID, blob, 2, PRIVATE_VAULT)).resolves.toEqual(PAYLOAD);
    await expect(session.decryptEntryForVault(CLIENT_ID, blob, 2, null)).rejects.toThrow();
  });

  it('al convertir una pública en privada se cifra ya con la subclave recién creada', async () => {
    const session = await unlockedSession();
    session.unlockVaultKey(PUBLIC_VAULT, await newKey());

    const blob = await session.encryptEntryForVault(CLIENT_ID, PAYLOAD, PUBLIC_VAULT);

    await expect(session.decryptEntryForVault(CLIENT_ID, blob, 2, null)).rejects.toThrow();
  });

  it('el dominio de una privada bloqueada es el suyo, no el principal', async () => {
    const session = await unlockedSession();

    // Si fuera 'main', mover a ella una entrada sin bóveda parecería no cambiar de dominio y se
    // enviaría el blob tal cual, cifrado con la principal.
    expect(session.keyDomainId(PRIVATE_VAULT)).toBe(`sub:${PRIVATE_VAULT}`);
    expect(session.keyDomainId(PUBLIC_VAULT)).toBe('main');
    expect(session.keyDomainId(null)).toBe('main');
    expect(() => session.keyDomainId(99)).toThrow();
  });
});

// ===========================================================================
// N9 — cableado: vaultService informa la privacidad y passwordService no envía nada
// ===========================================================================
describe('N9 — cableado con vaultService y passwordService', () => {
  const requests: { method: string; path: string }[] = [];

  beforeEach(async () => {
    requests.length = 0;
    vi.stubGlobal('fetch', async (input: RequestInfo | URL, init: RequestInit = {}) => {
      const path = new URL(String(input), 'http://localhost').pathname;
      const method = init.method ?? 'GET';
      requests.push({ method, path });
      const body = path === '/api/vaults/'
        ? {
            success: true,
            vaults: [
              { id: PRIVATE_VAULT, name: 'Privada', is_private: true },
              { id: PUBLIC_VAULT, name: 'Pública', is_private: false },
            ],
            unvaulted_passwords: 0,
          }
        : { success: true };
      return new Response(JSON.stringify(body), { headers: { 'Content-Type': 'application/json' } });
    });
    cryptoSession.unlock(await newKey(), USER_ID);
  });

  afterEach(() => {
    cryptoSession.lock();
    cryptoSession.forgetVault();
    vi.unstubAllGlobals();
  });

  it('getVaults() le dice a cryptoSession qué bóvedas son privadas', async () => {
    await vaultService.getVaults();

    await expect(cryptoSession.encryptEntryForVault(CLIENT_ID, PAYLOAD, PUBLIC_VAULT)).resolves.toBeTypeOf('string');
    await expect(cryptoSession.encryptEntryForVault(CLIENT_ID, PAYLOAD, PRIVATE_VAULT)).rejects.toMatchObject({
      code: 'VAULT_LOCKED',
    });
  });

  it('crear en una privada bloqueada falla sin enviar nada al servidor', async () => {
    await vaultService.getVaults();

    const result = await passwordService.createAccount({
      website: 'example.org',
      username: 'ana',
      password: 'Primera$Clave1',
      algorithm: 'AES',
      vault_id: PRIVATE_VAULT,
    });

    expect(result.success).toBe(false);
    expect(requests.filter((r) => r.path === '/api/passwords/add/')).toHaveLength(0);
  });
});

// ===========================================================================
// N13 — el autobloqueo no espera a que alguien pregunte
// ===========================================================================
describe('N13 — autobloqueo activo', () => {
  const IDLE_MS = 15 * 60 * 1000;
  let session: CryptoSession;
  let locked: ReturnType<typeof vi.fn>;

  beforeEach(async () => {
    const key = await newKey();
    vi.useFakeTimers();
    locked = vi.fn();
    window.addEventListener('vault:locked', locked);
    session = new CryptoSession();
    session.unlock(key, USER_ID);
  });

  afterEach(() => {
    session.lock();
    window.removeEventListener('vault:locked', locked);
    vi.useRealTimers();
  });

  it('15 min sin actividad → se bloquea solo y emite vault:locked, sin que nadie llame a isUnlocked', () => {
    vi.advanceTimersByTime(IDLE_MS - 30_000);
    expect(locked).not.toHaveBeenCalled();

    vi.advanceTimersByTime(30_000);
    expect(locked).toHaveBeenCalledTimes(1);
    expect(session.isUnlocked()).toBe(false);
    // Bloqueada, deja de vigilar: ni reloj ni nada que lo vuelva a disparar.
    expect(vi.getTimerCount()).toBe(0);
  });

  it('teclear, hacer clic o hacer scroll renueva los 15 min', () => {
    for (const type of ['keydown', 'pointerdown', 'wheel', 'touchstart']) {
      vi.advanceTimersByTime(10 * 60 * 1000);
      window.dispatchEvent(new Event(type));
    }
    vi.advanceTimersByTime(10 * 60 * 1000);
    expect(locked).not.toHaveBeenCalled();
    expect(session.isUnlocked()).toBe(true);

    vi.advanceTimersByTime(5 * 60 * 1000);
    expect(locked).toHaveBeenCalledTimes(1);
  });

  it('al volver a una pestaña oculta se bloquea en el acto si ya pasó el plazo', () => {
    // Los navegadores frenan los temporizadores de las pestañas ocultas: pasa el tiempo sin ticks.
    vi.setSystemTime(Date.now() + IDLE_MS + 1);
    expect(locked).not.toHaveBeenCalled();

    document.dispatchEvent(new Event('visibilitychange'));
    expect(locked).toHaveBeenCalledTimes(1);
  });

  it('una interacción tras el plazo no resucita la sesión', () => {
    vi.setSystemTime(Date.now() + IDLE_MS + 1);

    window.dispatchEvent(new Event('pointerdown'));
    expect(locked).toHaveBeenCalledTimes(1);
    expect(session.isUnlocked()).toBe(false);
  });
});
