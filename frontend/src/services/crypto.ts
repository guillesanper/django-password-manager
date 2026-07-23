/**
 * crypto.ts — Núcleo criptográfico zero-knowledge del cliente (Fase 2, §8 auditoría).
 *
 * La contraseña maestra NUNCA sale del navegador. El servidor sólo ve material opaco:
 *
 *   MK        = Argon2id(master_password, salt_usuario, m=64MiB, t=3, p=4)   [hash-wasm]
 *   AuthKey   = HKDF-SHA256(MK, info="auth")   → se envía al servidor (para verificar)
 *   EncKey    = HKDF-SHA256(MK, info="enc")    → nunca sale del navegador
 *   VaultKey  = 32 bytes aleatorios
 *   wrapped_vault_key = AES-256-GCM(EncKey, VaultKey)   → se guarda en el servidor
 *
 * Por entrada:  AES-256-GCM(VaultKey, plaintext), nonce aleatorio de 12 bytes,
 *               AAD = user_id | entry_id | crypto_version.
 *
 * Diseño para test: todo lo determinista (derivaciones, AEAD, formato de blob) son funciones
 * puras que dependen sólo de sus argumentos y de WebCrypto/hash-wasm. El estado con efectos
 * (VaultKey en memoria, auto-bloqueo) vive en `VaultSession`, con reloj inyectable.
 */

import { argon2id } from 'hash-wasm';

// ---------------------------------------------------------------------------
// Constantes
// ---------------------------------------------------------------------------

export const CRYPTO_VERSION = 2;

/** Parámetros KDF. `m` en KiB (65536 KiB = 64 MiB). Se guardan en UserCrypto.kdf_params
 *  para que un cambio futuro de coste no rompa las bóvedas ya derivadas. */
export const KDF_PARAMS = {
  algo: 'argon2id' as const,
  m: 65536, // 64 MiB
  t: 3,
  p: 4,
  hashLen: 32,
  version: 19, // Argon2 v1.3 (0x13)
} as const;

export type KdfParams = typeof KDF_PARAMS;

const NONCE_LEN = 12; // AES-GCM
const SALT_LEN = 16; // sal Argon2id por usuario
const FILE_CHUNK_SIZE = 1024 * 1024; // 1 MiB de texto claro por chunk

// ---------------------------------------------------------------------------
// Codificación (browser + Node, sin dependencias)
// ---------------------------------------------------------------------------

const _enc = new TextEncoder();
const _dec = new TextDecoder();

export const utf8 = (s: string): Uint8Array => _enc.encode(s);
export const fromUtf8 = (b: Uint8Array): string => _dec.decode(b);

export function toBase64(bytes: Uint8Array): string {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s);
}

export function fromBase64(b64: string): Uint8Array {
  const s = atob(b64);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

// ---------------------------------------------------------------------------
// Aleatoriedad
// ---------------------------------------------------------------------------

export function randomBytes(n: number): Uint8Array {
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return b;
}

export const generateSalt = (): Uint8Array => randomBytes(SALT_LEN);

// ---------------------------------------------------------------------------
// Derivación de claves
// ---------------------------------------------------------------------------

/** MK = Argon2id(master_password, salt). Devuelve 32 bytes crudos. */
export async function deriveMasterKey(
  masterPassword: string,
  salt: Uint8Array,
  params: KdfParams = KDF_PARAMS,
): Promise<Uint8Array> {
  return argon2id({
    password: masterPassword,
    salt,
    parallelism: params.p,
    iterations: params.t,
    memorySize: params.m,
    hashLength: params.hashLen,
    outputType: 'binary',
  });
}

/** HKDF-SHA256(ikm, info). Sal vacía: la MK ya es de alta entropía, sólo hace falta expandir
 *  a dos subclaves de dominio separado ("auth" / "enc"). */
async function hkdf(ikm: Uint8Array, info: string, length = 32): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: utf8(info) },
    key,
    length * 8,
  );
  return new Uint8Array(bits);
}

/** AuthKey = HKDF(MK, "auth"). Se envía al servidor en base64; allí se guarda su Argon2id. */
export const deriveAuthKey = (mk: Uint8Array): Promise<Uint8Array> => hkdf(mk, 'auth');

/** EncKey = HKDF(MK, "enc"). Nunca sale del navegador; envuelve la VaultKey. */
export const deriveEncKey = (mk: Uint8Array): Promise<Uint8Array> => hkdf(mk, 'enc');

// ---------------------------------------------------------------------------
// Primitivas AES-256-GCM
// ---------------------------------------------------------------------------

/** Importa 32 bytes crudos como clave AES-GCM. `extractable=false` salvo que se pida. */
export function importAesKey(raw: Uint8Array, extractable = false): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, extractable, [
    'encrypt',
    'decrypt',
  ]);
}

/** AES-256-GCM. Devuelve nonce(12) || ciphertext||tag. El tag va incluido por WebCrypto. */
export async function aesGcmEncrypt(
  key: CryptoKey,
  plaintext: Uint8Array,
  aad?: Uint8Array,
): Promise<Uint8Array> {
  const nonce = randomBytes(NONCE_LEN);
  const ct = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: nonce, additionalData: aad, tagLength: 128 },
      key,
      plaintext,
    ),
  );
  return concatBytes(nonce, ct);
}

/** Inversa de aesGcmEncrypt. Lanza si el tag no valida (manipulación) o la clave/AAD no casan. */
export async function aesGcmDecrypt(
  key: CryptoKey,
  blob: Uint8Array,
  aad?: Uint8Array,
): Promise<Uint8Array> {
  if (blob.length < NONCE_LEN + 16) throw new Error('Blob AEAD demasiado corto');
  const nonce = blob.subarray(0, NONCE_LEN);
  const ct = blob.subarray(NONCE_LEN);
  const pt = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: nonce, additionalData: aad, tagLength: 128 },
    key,
    ct,
  );
  return new Uint8Array(pt);
}

// ---------------------------------------------------------------------------
// VaultKey: generación, envoltura y desenvoltura
// ---------------------------------------------------------------------------

/** VaultKey aleatoria (32 bytes crudos). Se importa a CryptoKey con importVaultKey. */
export const generateVaultKey = (): Uint8Array => randomBytes(32);

/** Importa la VaultKey cruda para cifrar/descifrar entradas. No extraíble. */
export const importVaultKey = (raw: Uint8Array): Promise<CryptoKey> => importAesKey(raw, false);

/** wrapped_vault_key = AES-256-GCM(EncKey, VaultKey), en base64. */
export async function wrapVaultKey(
  encKey: Uint8Array,
  vaultKeyRaw: Uint8Array,
): Promise<string> {
  const k = await importAesKey(encKey, false);
  return toBase64(await aesGcmEncrypt(k, vaultKeyRaw));
}

/** Desenvuelve wrapped_vault_key. Lanza si la EncKey (derivada de la maestra) es incorrecta. */
export async function unwrapVaultKey(
  encKey: Uint8Array,
  wrappedB64: string,
): Promise<Uint8Array> {
  const k = await importAesKey(encKey, false);
  return aesGcmDecrypt(k, fromBase64(wrappedB64));
}

// ---------------------------------------------------------------------------
// Cifrado por entrada
// ---------------------------------------------------------------------------

/** AAD que liga el ciphertext a (usuario, entrada, versión): impide reubicar un blob de una
 *  entrada en otra o degradar la versión, incluso con acceso de escritura a la BD. */
export function buildEntryAAD(
  userId: number | string,
  entryId: number | string,
  version: number = CRYPTO_VERSION,
): Uint8Array {
  return utf8(`${userId}|${entryId}|${version}`);
}

/** Cifra el texto claro de una entrada con la VaultKey. Devuelve el blob AEAD en base64. */
export async function encryptEntry(
  vaultKey: CryptoKey,
  plaintext: string,
  aad: Uint8Array,
): Promise<string> {
  return toBase64(await aesGcmEncrypt(vaultKey, utf8(plaintext), aad));
}

/** Descifra el blob AEAD de una entrada. Lanza explícitamente si hay manipulación (no basura). */
export async function decryptEntry(
  vaultKey: CryptoKey,
  ciphertextB64: string,
  aad: Uint8Array,
): Promise<string> {
  return fromUtf8(await aesGcmDecrypt(vaultKey, fromBase64(ciphertextB64), aad));
}

// ---------------------------------------------------------------------------
// Orquestación de alto nivel
// ---------------------------------------------------------------------------

/** Material que se envía al servidor al crear/reestablecer la cripto del usuario. */
export interface UserCryptoSetup {
  kdfSalt: string; // base64
  kdfParams: KdfParams;
  authKey: string; // base64 — el servidor guarda su Argon2id
  wrappedVaultKey: string; // base64
  cryptoVersion: number;
}

/** Genera todo el material zero-knowledge para un usuario nuevo (o un reset de maestra).
 *  Devuelve lo enviable al servidor y la VaultKey ya importada en memoria. */
export async function setupUserCrypto(
  masterPassword: string,
  params: KdfParams = KDF_PARAMS,
): Promise<{ setup: UserCryptoSetup; vaultKey: CryptoKey }> {
  const salt = generateSalt();
  const mk = await deriveMasterKey(masterPassword, salt, params);
  const [authKey, encKey] = await Promise.all([deriveAuthKey(mk), deriveEncKey(mk)]);
  const vaultKeyRaw = generateVaultKey();
  const wrappedVaultKey = await wrapVaultKey(encKey, vaultKeyRaw);
  const vaultKey = await importVaultKey(vaultKeyRaw);
  return {
    setup: {
      kdfSalt: toBase64(salt),
      kdfParams: params,
      authKey: toBase64(authKey),
      wrappedVaultKey,
      cryptoVersion: CRYPTO_VERSION,
    },
    vaultKey,
  };
}

/** Desbloquea la bóveda a partir de la maestra y el material del servidor.
 *  Devuelve la VaultKey en memoria y la AuthKey (por si hay que probar posesión al servidor). */
export async function unlockVault(
  masterPassword: string,
  kdfSaltB64: string,
  wrappedVaultKeyB64: string,
  kdfParams: KdfParams = KDF_PARAMS,
): Promise<{ vaultKey: CryptoKey; authKey: string }> {
  const mk = await deriveMasterKey(masterPassword, fromBase64(kdfSaltB64), kdfParams);
  const [authKey, encKey] = await Promise.all([deriveAuthKey(mk), deriveEncKey(mk)]);
  const vaultKeyRaw = await unwrapVaultKey(encKey, wrappedVaultKeyB64); // lanza si la maestra es incorrecta
  const vaultKey = await importVaultKey(vaultKeyRaw);
  return { vaultKey, authKey: toBase64(authKey) };
}

/** Rotación de la maestra (paso 25): re-envuelve la MISMA VaultKey con la EncKey nueva.
 *  No re-cifra la bóveda. Devuelve el material nuevo para el servidor. Requiere la maestra
 *  actual para desenvolver la VaultKey vigente. */
export async function rotateMasterPassword(
  currentMasterPassword: string,
  currentKdfSaltB64: string,
  currentWrappedVaultKeyB64: string,
  newMasterPassword: string,
  currentKdfParams: KdfParams = KDF_PARAMS,
  newKdfParams: KdfParams = KDF_PARAMS,
): Promise<UserCryptoSetup> {
  const curMk = await deriveMasterKey(currentMasterPassword, fromBase64(currentKdfSaltB64), currentKdfParams);
  const curEncKey = await deriveEncKey(curMk);
  const vaultKeyRaw = await unwrapVaultKey(curEncKey, currentWrappedVaultKeyB64);

  const newSalt = generateSalt();
  const newMk = await deriveMasterKey(newMasterPassword, newSalt, newKdfParams);
  const [newAuthKey, newEncKey] = await Promise.all([deriveAuthKey(newMk), deriveEncKey(newMk)]);
  const wrappedVaultKey = await wrapVaultKey(newEncKey, vaultKeyRaw);

  return {
    kdfSalt: toBase64(newSalt),
    kdfParams: newKdfParams,
    authKey: toBase64(newAuthKey),
    wrappedVaultKey,
    cryptoVersion: CRYPTO_VERSION,
  };
}

// ---------------------------------------------------------------------------
// Cifrado de ficheros por chunks (AES-GCM)
// ---------------------------------------------------------------------------
//
// Cada fichero se cifra con una FileKey aleatoria propia; esa FileKey se envuelve con la
// VaultKey y se guarda (junto a los metadatos) en EncryptedFile.ciphertext. El contenido va a
// MinIO como blob opaco, troceado:
//
//   header: MAGIC(4) || version(1) || baseNonce(8)
//   por chunk i: AES-GCM(FileKey, chunk_i), nonce = baseNonce(8)||counter_BE(4),
//                AAD = counter_BE(4) || finalFlag(1)   (evita reordenado y truncado)
//
// La longitud de cada chunk cifrado es texto_claro + 16 (tag), salvo el último; el descifrador
// reconstruye los límites por el tamaño de chunk fijo del header.

const FILE_MAGIC = utf8('PMF1'); // Password-Manager File v1
const FILE_HEADER_LEN = FILE_MAGIC.length + 1 + 8;

export const generateFileKey = (): Uint8Array => randomBytes(32);

/** Envuelve la FileKey con la VaultKey → base64 (se guarda en EncryptedFile.ciphertext). */
export async function wrapFileKey(vaultKey: CryptoKey, fileKeyRaw: Uint8Array): Promise<string> {
  return toBase64(await aesGcmEncrypt(vaultKey, fileKeyRaw));
}

/** Desenvuelve la FileKey con la VaultKey. */
export async function unwrapFileKey(vaultKey: CryptoKey, wrappedB64: string): Promise<Uint8Array> {
  return aesGcmDecrypt(vaultKey, fromBase64(wrappedB64));
}

function chunkNonce(baseNonce: Uint8Array, counter: number): Uint8Array {
  const nonce = new Uint8Array(NONCE_LEN);
  nonce.set(baseNonce, 0); // 8 bytes
  new DataView(nonce.buffer).setUint32(8, counter, false); // 4 bytes BE
  return nonce;
}

function chunkAAD(counter: number, isFinal: boolean): Uint8Array {
  const aad = new Uint8Array(5);
  new DataView(aad.buffer).setUint32(0, counter, false);
  aad[4] = isFinal ? 1 : 0;
  return aad;
}

/** Cifra un Blob/File por chunks con una FileKey. Lee el origen de forma troceada
 *  (source.slice) para no cargarlo entero en RAM antes de tiempo. */
export async function encryptFile(
  fileKeyRaw: Uint8Array,
  source: Blob,
  chunkSize: number = FILE_CHUNK_SIZE,
): Promise<Blob> {
  const key = await importAesKey(fileKeyRaw, false);
  const baseNonce = randomBytes(8);
  const header = concatBytes(FILE_MAGIC, new Uint8Array([1]), baseNonce);
  const out: BlobPart[] = [header];

  const total = source.size;
  const nChunks = Math.max(1, Math.ceil(total / chunkSize));
  for (let i = 0; i < nChunks; i++) {
    const start = i * chunkSize;
    const end = Math.min(start + chunkSize, total);
    const plain = new Uint8Array(await source.slice(start, end).arrayBuffer());
    const isFinal = i === nChunks - 1;
    const ct = new Uint8Array(
      await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: chunkNonce(baseNonce, i), additionalData: chunkAAD(i, isFinal), tagLength: 128 },
        key,
        plain,
      ),
    );
    out.push(ct);
  }
  return new Blob(out, { type: 'application/octet-stream' });
}

/** Inversa de encryptFile. Lanza si falta un chunk, se reordena o se manipula (tag GCM + AAD). */
export async function decryptFile(
  fileKeyRaw: Uint8Array,
  encrypted: Blob,
  chunkSize: number = FILE_CHUNK_SIZE,
): Promise<Blob> {
  const key = await importAesKey(fileKeyRaw, false);
  const headerBytes = new Uint8Array(await encrypted.slice(0, FILE_HEADER_LEN).arrayBuffer());
  for (let i = 0; i < FILE_MAGIC.length; i++) {
    if (headerBytes[i] !== FILE_MAGIC[i]) throw new Error('Cabecera de fichero cifrado inválida');
  }
  const baseNonce = headerBytes.subarray(FILE_MAGIC.length + 1, FILE_HEADER_LEN);

  const encChunkSize = chunkSize + 16; // + tag
  const body = encrypted.slice(FILE_HEADER_LEN);
  const bodySize = body.size;
  const nChunks = Math.max(1, Math.ceil(bodySize / encChunkSize));
  const out: BlobPart[] = [];
  for (let i = 0; i < nChunks; i++) {
    const start = i * encChunkSize;
    const end = Math.min(start + encChunkSize, bodySize);
    const ct = new Uint8Array(await body.slice(start, end).arrayBuffer());
    const isFinal = i === nChunks - 1;
    const pt = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: chunkNonce(baseNonce, i), additionalData: chunkAAD(i, isFinal), tagLength: 128 },
      key,
      ct,
    );
    out.push(new Uint8Array(pt));
  }
  return new Blob(out);
}

// ---------------------------------------------------------------------------
// VaultSession — VaultKey en memoria con auto-bloqueo por inactividad
// ---------------------------------------------------------------------------
//
// La VaultKey vive SÓLO aquí, nunca en localStorage/sessionStorage. Se bloquea por
// inactividad. El reloj es inyectable para poder testear la expiración sin esperar.

export interface VaultSessionOptions {
  /** Milisegundos de inactividad tras los que la bóveda se bloquea. */
  idleTimeoutMs: number;
  /** Reloj inyectable (test). Por defecto Date.now. */
  now?: () => number;
  /** Callback al bloquear (p. ej. redirigir a la pantalla de desbloqueo). */
  onLock?: () => void;
}

export class VaultSession {
  private vaultKey: CryptoKey | null = null;
  private lastActivity = 0;
  private readonly now: () => number;
  private readonly opts: VaultSessionOptions;

  constructor(opts: VaultSessionOptions) {
    this.opts = opts;
    this.now = opts.now ?? (() => Date.now());
  }

  unlock(vaultKey: CryptoKey): void {
    this.vaultKey = vaultKey;
    this.lastActivity = this.now();
  }

  /** Renueva la marca de actividad. Llamar en cada operación cripto o interacción. */
  touch(): void {
    if (this.vaultKey) this.lastActivity = this.now();
  }

  private expired(): boolean {
    return this.now() - this.lastActivity >= this.opts.idleTimeoutMs;
  }

  isUnlocked(): boolean {
    if (!this.vaultKey) return false;
    if (this.expired()) {
      this.lock();
      return false;
    }
    return true;
  }

  /** Devuelve la VaultKey y renueva actividad. Lanza si está bloqueada o expiró. */
  getKey(): CryptoKey {
    if (!this.isUnlocked()) throw new Error('La bóveda está bloqueada');
    this.touch();
    return this.vaultKey as CryptoKey;
  }

  /** Milisegundos que quedan hasta el auto-bloqueo (0 si ya bloqueada). */
  remainingMs(): number {
    if (!this.vaultKey) return 0;
    return Math.max(0, this.opts.idleTimeoutMs - (this.now() - this.lastActivity));
  }

  lock(): void {
    if (this.vaultKey) {
      this.vaultKey = null;
      this.lastActivity = 0;
      this.opts.onLock?.();
    }
  }
}
