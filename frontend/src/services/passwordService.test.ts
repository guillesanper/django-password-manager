/**
 * passwordService.test.ts — L3 (vitest / jsdom). Cableado cliente↔servidor de las contraseñas.
 *
 * crypto.test.ts prueba las primitivas; aquí corre el passwordService REAL, con su cifrado real,
 * contra un servidor falso en memoria que reproduce el contrato de `password_views.py`: guarda
 * blobs opacos y conserva el client_id de cada entrada. Es lo que ningún otro nivel ejercita:
 * L1 y L2 fabrican el ciphertext en Python, así que no ven qué AAD usa de verdad el cliente.
 *
 * Cubre:
 *   N8 — editar conserva el client_id. Antes, updatePassword re-cifraba con un client_id nuevo
 *        en la AAD, el servidor guardaba el viejo y la entrada dejaba de descifrarse: desaparecía
 *        de la lista sin ningún error visible (toAccount se traga el fallo con console.warn).
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { cryptoSession } from './cryptoSession';
import { generateVaultKey, importVaultKey } from './crypto';
import { passwordService } from './passwordService';

const USER_ID = 7;

interface StoredEntry {
  id: number;
  client_id: string;
  ciphertext: string;
  crypto_version: number;
  vault_id: number | null;
  created_at: string;
  updated_at: string;
}

/** Cuerpo JSON de las peticiones que envía passwordService a estas rutas. */
interface RequestBody {
  client_id?: string;
  ciphertext?: string;
  crypto_version?: number;
  vault_id?: number | null;
}

interface RecordedRequest {
  method: string;
  path: string;
  body: RequestBody;
}

const json = (data: unknown, status = 200): Response =>
  new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json' } });

/** Servidor en memoria con el contrato de `password_views.py` para las rutas que se usan aquí. */
class FakeServer {
  readonly entries = new Map<number, StoredEntry>();
  readonly requests: RecordedRequest[] = [];
  private nextId = 1;

  readonly fetch = async (input: RequestInfo | URL, init: RequestInit = {}): Promise<Response> => {
    const path = new URL(String(input), 'http://localhost').pathname;
    const method = init.method ?? 'GET';
    const body: RequestBody = init.body ? JSON.parse(String(init.body)) : {};
    this.requests.push({ method, path, body });

    if (method === 'GET' && path === '/api/accounts/') {
      return json({ success: true, accounts: [...this.entries.values()] });
    }

    if (method === 'POST' && path === '/api/passwords/add/') {
      if ([...this.entries.values()].some((e) => e.client_id === body.client_id)) {
        return json({ success: false, error: 'client_id duplicado' }, 400);
      }
      const now = new Date().toISOString();
      const entry: StoredEntry = {
        id: this.nextId++,
        client_id: String(body.client_id),
        ciphertext: String(body.ciphertext),
        crypto_version: Number(body.crypto_version),
        vault_id: body.vault_id ?? null,
        created_at: now,
        updated_at: now,
      };
      this.entries.set(entry.id, entry);
      return json({ success: true, password_id: entry.id, client_id: entry.client_id });
    }

    const update = path.match(/^\/api\/passwords\/(\d+)\/update\/$/);
    if (method === 'POST' && update) {
      const entry = this.entries.get(Number(update[1]));
      if (!entry) return json({ success: false, error: 'Contraseña no encontrada' }, 404);
      if (body.client_id !== entry.client_id) {
        return json({ success: false, error: 'client_id no coincide con el de la entrada' }, 400);
      }
      // Como el servidor real: sustituye el blob y conserva el client_id guardado.
      entry.ciphertext = String(body.ciphertext);
      entry.crypto_version = Number(body.crypto_version);
      entry.updated_at = new Date().toISOString();
      return json({ success: true });
    }

    return json({ success: false, error: `ruta no simulada: ${method} ${path}` }, 404);
  };

  requestsTo(path: string): RecordedRequest[] {
    return this.requests.filter((r) => r.path === path);
  }
}

let server: FakeServer;

beforeEach(async () => {
  server = new FakeServer();
  vi.stubGlobal('fetch', server.fetch);
  cryptoSession.unlock(await importVaultKey(generateVaultKey()), USER_ID);
});

afterEach(() => {
  cryptoSession.lock();
  vi.unstubAllGlobals();
});

async function createEntry(): Promise<StoredEntry> {
  const created = await passwordService.createAccount({
    website: 'https://www.example.org',
    username: 'ana',
    password: 'Primera$Clave1',
    algorithm: 'AES',
  });
  expect(created.success).toBe(true);
  const [entry] = server.entries.values();
  return { ...entry };
}

// ===========================================================================
// N8 — editar conserva el client_id
// ===========================================================================
describe('N8 — editar una contraseña conserva su client_id', () => {
  it('crear → editar → getAccounts() devuelve la entrada editada', async () => {
    const before = await createEntry();

    const updated = await passwordService.updatePassword(before.id, {
      website: 'example.org',
      username: 'ana.garcia',
      password: 'Segunda$Clave2',
    });
    expect(updated.success).toBe(true);

    const accounts = await passwordService.getAccounts();
    expect(accounts).toHaveLength(1);
    expect(accounts[0]).toMatchObject({
      id: before.id,
      website: 'example.org',
      username: 'ana.garcia',
      decrypted_password: 'Segunda$Clave2',
    });
  });

  it('re-cifra con el client_id guardado y sustituye el blob', async () => {
    const before = await createEntry();

    await passwordService.updatePassword(before.id, {
      website: 'example.org',
      username: 'ana',
      password: 'Segunda$Clave2',
    });

    const [request] = server.requestsTo(`/api/passwords/${before.id}/update/`);
    expect(request.body.client_id).toBe(before.client_id);
    expect(server.entries.get(before.id)?.ciphertext).not.toBe(before.ciphertext);
  });

  it('una entrada que el servidor no devuelve no se re-cifra ni se envía', async () => {
    const result = await passwordService.updatePassword(999, {
      website: 'example.org',
      username: 'ana',
      password: 'Segunda$Clave2',
    });

    expect(result).toEqual({ success: false, error: 'Contraseña no encontrada' });
    expect(server.requestsTo('/api/passwords/999/update/')).toHaveLength(0);
  });
});
