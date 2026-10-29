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
// Cada cuánto se mira si ya toca bloquear (N13). VaultSession sólo caduca cuando alguien le
// pregunta: sin este reloj, una pestaña abierta con contraseñas en pantalla nunca se bloqueaba.
const LOCK_CHECK_INTERVAL_MS = 30 * 1000;
// Interacciones que cuentan como actividad. Antes sólo la renovaban las operaciones cripto, que
// con un reloj activo bloquearía a quien lleva 15 min leyendo o copiando la lista ya descifrada.
const ACTIVITY_EVENTS = ['pointerdown', 'keydown', 'wheel', 'touchstart'] as const;

/** Error al cifrar para una bóveda cuyo dominio de clave no se tiene (N9). Lleva `code` como los
 *  errores del servidor, para que la UI lo trate igual que un `VAULT_LOCKED`. */
function keyDomainUnavailable(vaultId: number, privacyKnown: boolean): Error {
  const err = new Error(
    privacyKnown
      ? 'La bóveda privada está bloqueada. Desbloquéala para guardar en ella.'
      : `No se conoce la bóveda ${vaultId}. Recarga la lista de bóvedas e inténtalo de nuevo.`,
  );
  (err as Error & { code?: string }).code = 'VAULT_LOCKED';
  return err;
}

export class CryptoSession {
  // VaultSubKeys de bóvedas privadas desbloqueadas (paso 24), en el mismo ciclo de vida que la
  // VaultKey principal: se vacían al bloquear (manual, logout o auto-bloqueo por inactividad).
  private subKeys = new Map<number, CryptoKey>();
  private session = new VaultSession({
    idleTimeoutMs: IDLE_TIMEOUT_MS,
    onLock: () => {
      this.subKeys.clear();
      this.stopLockWatch();
      window.dispatchEvent(new CustomEvent('vault:locked'));
    },
  });
  private lockCheck: ReturnType<typeof setInterval> | null = null;
  private userId: number | null = null;
  // Privacidad de cada bóveda conocida (N9). No es secreta: la da `/api/vaults/`. Sirve para elegir
  // la clave al CIFRAR, donde no se puede adivinar: con una bóveda privada sin subclave, caer a la
  // VaultKey principal guardaba en la bóveda entradas que sólo protegía la maestra. No se vacía
  // con el auto-bloqueo (la lista de bóvedas no se vuelve a pedir al desbloquear), sólo al
  // cerrar sesión.
  private vaultPrivacy = new Map<number, boolean>();

  /** Registra la VaultKey desbloqueada y el usuario. Lo llama masterKeyService. */
  unlock(vaultKey: CryptoKey, userId: number): void {
    this.session.unlock(vaultKey);
    this.userId = userId;
    this.startLockWatch();
  }

  // isUnlocked() es quien bloquea (y dispara `vault:locked`) si ya pasó el plazo.
  private readonly checkLock = (): void => {
    this.session.isUnlocked();
  };

  // Se comprueba antes de renovar: una interacción no resucita una sesión que ya caducó entre
  // dos ticks del reloj.
  private readonly onActivity = (): void => {
    if (this.session.isUnlocked()) this.session.touch();
  };

  /** Bloqueo activo (N13) mientras la bóveda está abierta: el reloj, más `visibilitychange`
   *  porque los navegadores frenan los temporizadores de las pestañas ocultas: al volver a una,
   *  se bloquea en el acto si el plazo ya pasó. */
  private startLockWatch(): void {
    if (this.lockCheck !== null) return;
    this.lockCheck = setInterval(this.checkLock, LOCK_CHECK_INTERVAL_MS);
    document.addEventListener('visibilitychange', this.checkLock);
    for (const type of ACTIVITY_EVENTS) {
      window.addEventListener(type, this.onActivity, { capture: true, passive: true });
    }
  }

  private stopLockWatch(): void {
    if (this.lockCheck === null) return;
    clearInterval(this.lockCheck);
    this.lockCheck = null;
    document.removeEventListener('visibilitychange', this.checkLock);
    for (const type of ACTIVITY_EVENTS) {
      window.removeEventListener(type, this.onActivity, { capture: true });
    }
  }

  lock(): void {
    this.subKeys.clear();
    this.session.lock();
    this.userId = null;
  }

  /** Registra si cada bóveda es privada. Lo alimenta vaultService con lo que devuelve el servidor
   *  (lista, creación y conversión). */
  setVaultPrivacy(vaultId: number, isPrivate: boolean): void {
    this.vaultPrivacy.set(vaultId, isPrivate);
  }

  /** Olvida una bóveda que ya no existe (o todas, al cerrar sesión). */
  forgetVault(vaultId?: number): void {
    if (vaultId == null) {
      this.vaultPrivacy.clear();
      this.subKeys.clear();
      return;
    }
    this.vaultPrivacy.delete(vaultId);
    this.subKeys.delete(vaultId);
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

  /** True si hay subclave en memoria para esa bóveda y la sesión sigue desbloqueada. */
  hasVaultKey(vaultId: number): boolean {
    return this.session.isUnlocked() && this.subKeys.has(vaultId);
  }

  /** Identidad del dominio de clave de una bóveda: 'main' (VaultKey principal) o 'sub:<id>' (su
   *  VaultSubKey). Dos entradas con el mismo dominio comparten clave; mover entre dominios
   *  distintos obliga a re-cifrar (paso 24b).
   *
   *  Una bóveda privada es 'sub:<id>' AUNQUE no esté desbloqueada: antes se decidía por tener la
   *  subclave, y mover a una privada bloqueada parecía no cambiar de dominio (N9). El dominio de
   *  una bóveda de privacidad desconocida no se adivina: lanza. */
  keyDomainId(vaultId: number | null): string {
    if (vaultId == null) return 'main';
    if (this.subKeys.has(vaultId)) return `sub:${vaultId}`;
    const isPrivate = this.vaultPrivacy.get(vaultId);
    if (isPrivate === undefined) throw keyDomainUnavailable(vaultId, false);
    return isPrivate ? `sub:${vaultId}` : 'main';
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

  /** Elige la clave para DESCIFRAR una entrada según su bóveda: la VaultSubKey si esa bóveda
   *  privada está desbloqueada, o la VaultKey principal en caso contrario. Es seguro caer a la
   *  principal: si la entrada estaba cifrada bajo una subclave, AES-GCM fallará el tag (no devuelve
   *  basura), así que como mucho la entrada queda oculta, nunca se descifra con la clave
   *  equivocada. Para cifrar no vale: ver `keyForEncrypt`. */
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

  /** Elige la clave para CIFRAR una entrada de una bóveda (N9). A diferencia de `keyForVault`, no
   *  cae a la VaultKey principal por defecto: un blob cifrado con la clave equivocada no falla al
   *  guardarse, sino que deja la entrada de una bóveda privada protegida sólo por la maestra.
   *
   *  - con la subclave en memoria → la subclave (también si la bóveda aún consta como pública: es
   *    el paso intermedio de convertirla en privada);
   *  - bóveda que se sabe pública → la VaultKey principal;
   *  - privada sin subclave, o de privacidad desconocida → lanza (fail-closed). */
  private keyForEncrypt(vaultId: number | null): CryptoKey {
    if (!this.session.isUnlocked() || this.userId == null) throw new Error('VAULT_LOCKED');
    if (vaultId == null) return this.session.getKey();
    const sub = this.subKeys.get(vaultId);
    if (sub) {
      this.session.touch();
      return sub;
    }
    const isPrivate = this.vaultPrivacy.get(vaultId);
    if (isPrivate === false) return this.session.getKey();
    throw keyDomainUnavailable(vaultId, isPrivate === true);
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
   *  bóveda es privada y no está desbloqueada, o si no se sabe si lo es (N9). */
  async encryptEntryForVault(
    clientId: string,
    payload: EntryPayload,
    vaultId: number | null,
  ): Promise<string> {
    const key = this.keyForEncrypt(vaultId);
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
    cryptoSession.forgetVault();
  });
}

export default cryptoSession;
