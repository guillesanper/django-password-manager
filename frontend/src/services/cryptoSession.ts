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
  // VaultSubKeys de bóvedas privadas desbloqueadas (paso 24), en el mismo ciclo de vida que la
  // VaultKey principal: se vacían al bloquear (manual, logout o auto-bloqueo por inactividad).
  private subKeys = new Map<number, CryptoKey>();
  // Privacidad de cada bóveda conocida (N9): decide si cifrar para ella sin subclave en memoria
  // es legítimo (pública → VaultKey principal) o no (privada bloqueada). No es secreto: el
  // servidor la entrega en cada listado. La alimenta vaultService.
  private vaultPrivacy = new Map<number, boolean>();
  private session = new VaultSession({
    idleTimeoutMs: IDLE_TIMEOUT_MS,
    onLock: () => {
      this.subKeys.clear();
      window.dispatchEvent(new CustomEvent('vault:locked'));
    },
  });
  private userId: number | null = null;

  /** Registra la VaultKey desbloqueada y el usuario. Lo llama masterKeyService. */
  unlock(vaultKey: CryptoKey, userId: number): void {
    this.session.unlock(vaultKey);
    this.userId = userId;
  }

  lock(): void {
    this.subKeys.clear();
    this.session.lock();
    this.userId = null;
  }

  /** Registra la VaultSubKey de una bóveda privada recién desbloqueada (paso 24). */
  unlockVaultKey(vaultId: number, subKey: CryptoKey): void {
    this.subKeys.set(vaultId, subKey);
    this.session.touch();
  }

  /** Olvida la subclave de una bóveda (al bloquearla o cambiar su contraseña). */
  lockVaultKey(vaultId: number): void {
    this.subKeys.delete(vaultId);
  }

  /** Registra la privacidad de las bóvedas tal como las lista el servidor. */
  trackVaults(vaults: ReadonlyArray<{ id: number; is_private: boolean }>): void {
    for (const v of vaults) this.vaultPrivacy.set(v.id, v.is_private);
  }

  /** Olvida las bóvedas conocidas (al cerrar sesión). */
  forgetVaults(): void {
    this.vaultPrivacy.clear();
  }

  /** True si hay subclave en memoria para esa bóveda y la sesión sigue desbloqueada. */
  hasVaultKey(vaultId: number): boolean {
    return this.session.isUnlocked() && this.subKeys.has(vaultId);
  }

  /** Identidad del dominio de clave de una bóveda: 'main' (VaultKey principal) o 'sub:<id>' si es
   *  privada, esté o no desbloqueada en este cliente. Dos entradas con el mismo dominio comparten
   *  clave; mover entre dominios distintos obliga a re-cifrar (paso 24b). */
  keyDomainId(vaultId: number | null): string {
    if (vaultId == null) return 'main';
    return this.subKeys.has(vaultId) || this.vaultPrivacy.get(vaultId) ? `sub:${vaultId}` : 'main';
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

  /** Elige la clave de una entrada según su bóveda: la VaultSubKey si esa bóveda privada está
   *  desbloqueada, o la VaultKey principal en caso contrario. Es seguro caer a la principal: si
   *  la entrada estaba cifrada bajo una subclave, AES-GCM fallará el tag (no devuelve basura),
   *  así que como mucho la entrada queda oculta, nunca se descifra con la clave equivocada. */
  private keyForVault(vaultId: number | null): CryptoKey {
    if (!this.session.isUnlocked() || this.userId == null) throw new Error('VAULT_LOCKED');
    if (vaultId != null) {
      const sub = this.subKeys.get(vaultId);
      if (sub) {
        this.session.touch();
        return sub;
      }
    }
    return this.session.getKey();
  }

  /** Elige la clave para CIFRAR una entrada de una bóveda. A diferencia del descifrado, aquí no
   *  se puede caer a la VaultKey principal a ciegas (N9): una entrada nueva de una bóveda privada
   *  cifrada con la principal quedaría guardada en ella protegida sólo por la maestra. Sin
   *  subclave, sólo se usa la principal si se sabe que la bóveda es pública. */
  private encryptionKeyForVault(vaultId: number | null): CryptoKey {
    if (vaultId == null || this.subKeys.has(vaultId)) return this.keyForVault(vaultId);
    const isPrivate = this.vaultPrivacy.get(vaultId);
    if (isPrivate === false) return this.keyForVault(vaultId);
    throw new Error(
      isPrivate
        ? 'La bóveda privada está bloqueada. Desbloquéala primero.'
        : 'Bóveda desconocida. Recarga la lista de bóvedas e inténtalo de nuevo.',
    );
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

  /** Cifra una entrada eligiendo la clave por su bóveda (principal o VaultSubKey). Lanza si la
   *  bóveda es privada y su subclave no está en memoria, o si no se sabe si es privada. */
  async encryptEntryForVault(
    clientId: string,
    payload: EntryPayload,
    vaultId: number | null,
  ): Promise<string> {
    const key = this.encryptionKeyForVault(vaultId);
    const aad = buildEntryAAD(this.userIdOrThrow(), clientId, CRYPTO_VERSION);
    return encryptEntry(key, JSON.stringify(payload), aad);
  }

  /** Descifra una entrada eligiendo la clave por su bóveda (principal o VaultSubKey). */
  async decryptEntryForVault(
    clientId: string,
    ciphertext: string,
    version: number,
    vaultId: number | null,
  ): Promise<EntryPayload> {
    const key = this.keyForVault(vaultId);
    const aad = buildEntryAAD(this.userIdOrThrow(), clientId, version);
    return JSON.parse(await decryptEntry(key, ciphertext, aad)) as EntryPayload;
  }

  // Variantes sobre la VaultKey principal (bóveda pública / sin bóveda).
  encryptEntry(clientId: string, payload: EntryPayload): Promise<string> {
    return this.encryptEntryForVault(clientId, payload, null);
  }

  decryptEntry(
    clientId: string,
    ciphertext: string,
    version: number = CRYPTO_VERSION,
  ): Promise<EntryPayload> {
    return this.decryptEntryForVault(clientId, ciphertext, version, null);
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
  window.addEventListener('auth:logout', () => {
    cryptoSession.lock();
    cryptoSession.forgetVaults();
  });
}

export default cryptoSession;
