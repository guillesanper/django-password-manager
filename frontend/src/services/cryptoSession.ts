/**
 * cryptoSession.ts — Estado criptográfico en memoria de la sesión (Fase 2).
 *
 * Guarda la VaultKey desbloqueada (vía crypto.ts::VaultSession, nunca en localStorage) y el
 * user_id necesario para la AAD. Es un singleton porque los servicios (passwordService,
 * fileService...) no son componentes React y necesitan un punto de acceso común.
 *
 * El desbloqueo/rellenado de la VaultKey lo hace masterKeyService (que sabe pedir el material
 * al servidor); aquí sólo se custodia y se ofrecen los helpers de cifrado por entrada/fichero.
 */

import {
  VaultSession,
  buildEntryAAD,
  encryptEntry,
  decryptEntry,
  aesGcmEncrypt,
  aesGcmDecrypt,
  toBase64,
  fromBase64,
  utf8,
  fromUtf8,
  CRYPTO_VERSION,
} from './crypto';

/** Contenido cifrado de una entrada de contraseña (dentro del blob AEAD). */
export interface EntryPayload {
  website: string;
  username: string;
  password: string;
  notes?: string;
}

/** Metadatos cifrados de un fichero (dentro del blob AEAD). La FileKey va aquí, envuelta. */
export interface FileMeta {
  filename: string;
  contentType: string;
  size: number;
  fileKey: string; // base64 de la FileKey (32 bytes)
}

const IDLE_TIMEOUT_MS = 15 * 60 * 1000; // auto-bloqueo a los 15 min de inactividad

export class CryptoSession {
  private session = new VaultSession({
    idleTimeoutMs: IDLE_TIMEOUT_MS,
    onLock: () => window.dispatchEvent(new CustomEvent('vault:locked')),
  });
  private userId: number | null = null;

  /** Registra la VaultKey desbloqueada y el usuario. Lo llama masterKeyService. */
  unlock(vaultKey: CryptoKey, userId: number): void {
    this.session.unlock(vaultKey);
    this.userId = userId;
  }

  lock(): void {
    this.session.lock();
    this.userId = null;
  }

  isUnlocked(): boolean {
    return this.session.isUnlocked();
  }

  remainingMs(): number {
    return this.session.remainingMs();
  }

  private key(): CryptoKey {
    if (!this.session.isUnlocked() || this.userId == null) {
      throw new Error('VAULT_LOCKED');
    }
    return this.session.getKey();
  }

  private userIdOrThrow(): number {
    if (this.userId == null) throw new Error('VAULT_LOCKED');
    return this.userId;
  }

  /** UUID estable de cliente para una entrada/fichero nuevos (parte de la AAD). */
  newClientId(): string {
    return crypto.randomUUID();
  }

  // --- Entradas de contraseña ---

  async encryptEntry(clientId: string, payload: EntryPayload): Promise<string> {
    const key = this.key();
    const aad = buildEntryAAD(this.userIdOrThrow(), clientId, CRYPTO_VERSION);
    return encryptEntry(key, JSON.stringify(payload), aad);
  }

  async decryptEntry(
    clientId: string,
    ciphertext: string,
    version: number = CRYPTO_VERSION,
  ): Promise<EntryPayload> {
    const key = this.key();
    const aad = buildEntryAAD(this.userIdOrThrow(), clientId, version);
    return JSON.parse(await decryptEntry(key, ciphertext, aad)) as EntryPayload;
  }

  // --- Metadatos de fichero ---

  async wrapFileMeta(clientId: string, meta: FileMeta): Promise<string> {
    const key = this.key();
    const aad = buildEntryAAD(this.userIdOrThrow(), clientId, CRYPTO_VERSION);
    return toBase64(await aesGcmEncrypt(key, utf8(JSON.stringify(meta)), aad));
  }

  async unwrapFileMeta(
    clientId: string,
    ciphertext: string,
    version: number = CRYPTO_VERSION,
  ): Promise<FileMeta> {
    const key = this.key();
    const aad = buildEntryAAD(this.userIdOrThrow(), clientId, version);
    return JSON.parse(fromUtf8(await aesGcmDecrypt(key, fromBase64(ciphertext), aad))) as FileMeta;
  }
}

export const cryptoSession = new CryptoSession();

// Al cerrar sesión, la VaultKey debe desaparecer de memoria de inmediato.
if (typeof window !== 'undefined') {
  window.addEventListener('auth:logout', () => cryptoSession.lock());
}

export default cryptoSession;
