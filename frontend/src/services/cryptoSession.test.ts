/**
 * cryptoSession.test.ts — L3 (vitest / jsdom). Elección de clave por bóveda.
 *
 * Cubre, contra el cryptoSession REAL:
 *   N9 — no cifrar para una bóveda privada con la VaultKey principal. Antes, sin la subclave en
 *        memoria, encryptEntryForVault caía a la principal: un segundo navegador que sólo conocía
 *        la maestra guardaba entradas "privadas" protegidas únicamente por ella. Ahora lanza, y
 *        sólo cae a la principal si sabe que la bóveda es pública (la privacidad la registra
 *        vaultService con cada listado).
 *
 * El descifrado sí puede caer a la principal: con la clave equivocada AES-GCM falla el tag, nunca
 * devuelve contenido.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { CryptoSession, cryptoSession, type EntryPayload } from './cryptoSession';
import { generateVaultKey, importVaultKey } from './crypto';
import { vaultService } from './vaultService';

const USER_ID = 7;
const PUBLICA = 10;
const PRIVADA = 20;
const CLIENT_ID = '1f0e8d2c-3b4a-4c5d-8e6f-7a8b9c0d1e2f';
const PAYLOAD: EntryPayload = { website: 'example.org', username: 'ana', password: 'Clave$Segura1' };

const newKey = () => importVaultKey(generateVaultKey());

let session: CryptoSession;

beforeEach(async () => {
  session = new CryptoSession();
  session.unlock(await newKey(), USER_ID);
});

// ===========================================================================
// N9 — cifrar para una bóveda privada exige su subclave
// ===========================================================================
describe('N9 — cifrar para una bóveda privada exige su subclave', () => {
  it('privada sin subclave en memoria → lanza en vez de usar la principal', async () => {
    session.trackVaults([{ id: PRIVADA, is_private: true }]);

    await expect(session.encryptEntryForVault(CLIENT_ID, PAYLOAD, PRIVADA)).rejects.toThrow(
      /privada está bloqueada/,
    );
  });

  it('bóveda de privacidad desconocida → lanza (fail-closed)', async () => {
    await expect(session.encryptEntryForVault(CLIENT_ID, PAYLOAD, PRIVADA)).rejects.toThrow(
      /desconocida/,
    );
  });

  it('privada con subclave → cifra bajo la subclave, no bajo la principal', async () => {
    session.trackVaults([{ id: PRIVADA, is_private: true }]);
    session.unlockVaultKey(PRIVADA, await newKey());

    const blob = await session.encryptEntryForVault(CLIENT_ID, PAYLOAD, PRIVADA);

    await expect(session.decryptEntryForVault(CLIENT_ID, blob, 2, PRIVADA)).resolves.toEqual(PAYLOAD);
    await expect(session.decryptEntryForVault(CLIENT_ID, blob, 2, null)).rejects.toThrow();
  });

  it('pública conocida → cifra bajo la principal', async () => {
    session.trackVaults([{ id: PUBLICA, is_private: false }]);

    const blob = await session.encryptEntryForVault(CLIENT_ID, PAYLOAD, PUBLICA);

    await expect(session.decryptEntryForVault(CLIENT_ID, blob, 2, null)).resolves.toEqual(PAYLOAD);
  });

  it('sin bóveda → cifra bajo la principal sin necesidad de registro', async () => {
    const blob = await session.encryptEntryForVault(CLIENT_ID, PAYLOAD, null);

    await expect(session.decryptEntryForVault(CLIENT_ID, blob, 2, null)).resolves.toEqual(PAYLOAD);
  });

  it('una privada bloqueada es otro dominio de clave: moverla obliga a re-cifrar', () => {
    session.trackVaults([
      { id: PUBLICA, is_private: false },
      { id: PRIVADA, is_private: true },
    ]);

    expect(session.keyDomainId(PRIVADA)).toBe(`sub:${PRIVADA}`);
    expect(session.keyDomainId(PUBLICA)).toBe(session.keyDomainId(null));
  });
});

// ===========================================================================
// N9 — quién alimenta el registro de privacidad
// ===========================================================================
describe('N9 — el registro de privacidad lo alimenta vaultService y se vacía al cerrar sesión', () => {
  beforeEach(async () => {
    cryptoSession.unlock(await newKey(), USER_ID);
    vi.stubGlobal('fetch', async () =>
      new Response(
        JSON.stringify({
          success: true,
          vaults: [
            { id: PUBLICA, is_private: false },
            { id: PRIVADA, is_private: true },
          ],
        }),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      ),
    );
  });

  afterEach(() => {
    window.dispatchEvent(new CustomEvent('auth:logout'));
    vi.unstubAllGlobals();
  });

  it('getVaults() registra qué bóvedas son privadas', async () => {
    await vaultService.getVaults();

    await expect(cryptoSession.encryptEntryForVault(CLIENT_ID, PAYLOAD, PUBLICA)).resolves.toBeTruthy();
    await expect(cryptoSession.encryptEntryForVault(CLIENT_ID, PAYLOAD, PRIVADA)).rejects.toThrow(
      /privada está bloqueada/,
    );
  });

  it('auth:logout olvida las bóvedas conocidas', async () => {
    await vaultService.getVaults();

    window.dispatchEvent(new CustomEvent('auth:logout'));
    cryptoSession.unlock(await newKey(), USER_ID);

    await expect(cryptoSession.encryptEntryForVault(CLIENT_ID, PAYLOAD, PUBLICA)).rejects.toThrow(
      /desconocida/,
    );
  });
});
