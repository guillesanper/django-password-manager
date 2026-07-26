/**
 * crypto.test.ts — L3 (vitest / jsdom). Núcleo zero-knowledge del cliente.
 *
 * Cubre, contra el código REAL de crypto.ts (no contra la auditoría):
 *   Z2 / C6(AEAD)  — voltear un byte del ciphertext → decrypt LANZA (no devuelve basura).
 *   Z3            — round-trip de derivación y de wrap/unwrap; MK determinista.
 *   Z4            — vector KDF fijo (compartido con el helper Python de L1, trampa 14).
 *   Z9            — AAD atada a (user_id|entry_id|version): un blob reubicado no abre.
 *   Z13           — cifrado de ficheros por chunks > 1 MiB, round-trip byte a byte + antimanipulación.
 *   A8-b          — KDF del cliente es Argon2id con KDF_PARAMS (m=65536,t=3,p=4,v=19).
 *   G11           — crypto.ts importa y compila bajo el bundle de vitest.
 *   Z14 (forma)   — PUNTO CIEGO: wrap/unwrap sin AAD; se afirma la FORMA del código (el guardián
 *                   `if (aad !== undefined)`), no el bug del navegador. Verificación real: L4.
 * Además: cobertura de rotación de maestra, subclave de bóveda privada y VaultSession
 *   (parte L3 de Z15), para el objetivo ≥90% de §5.1.
 *
 * PUNTO CIEGO declarado (PLAN-DE-PRUEBAS.md §8): vitest corre en Node/jsdom, MÁS permisivo que
 * el navegador con AES-GCM sin additionalData. Estos tests NO reproducen el bug del 25-jul.
 */
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, it, expect, vi } from 'vitest';
import {
  CRYPTO_VERSION,
  KDF_PARAMS,
  deriveMasterKey,
  deriveAuthKey,
  deriveEncKey,
  importAesKey,
  aesGcmEncrypt,
  aesGcmDecrypt,
  wrapVaultKey,
  unwrapVaultKey,
  buildEntryAAD,
  encryptEntry,
  decryptEntry,
  setupUserCrypto,
  unlockVault,
  rotateMasterPassword,
  setupVaultSubKey,
  unlockVaultSubKey,
  rotateVaultPassword,
  generateFileKey,
  wrapFileKey,
  unwrapFileKey,
  encryptFile,
  decryptFile,
  generateSalt,
  generateVaultKey,
  importVaultKey,
  randomBytes,
  toBase64,
  fromBase64,
  utf8,
  fromUtf8,
  VaultSession,
} from './crypto';

// ---------------------------------------------------------------------------
// Vector KDF fijo de Z4 — COMPARTIDO con el helper de derivación Python del conftest de L1
// (trampa 14). Si Python y crypto.ts divergen, salta el test que compara este vector, no 20.
// Reproducir en Python: Argon2id(password, salt, m=65536 KiB, t=3, p=4, hashLen=32, v=0x13)
// crudo → HKDF-SHA256(mk, salt="", info="auth"/"enc", 32 bytes).
// ---------------------------------------------------------------------------
const Z4_VECTOR = {
  password: 'correct horse battery staple',
  saltB64: 'AAECAwQFBgcICQoLDA0ODw==', // 16 bytes: 0x00..0x0f
  mkHex: '853b272a44db1421c02962669a55eb0994f3cab385ed1c4c79253eee19bab49e',
  authKeyHex: '8a0730bfd3e742930ccc9e42cc2fedc203a56f0f118f6c7776ac7b984b7f8ae0',
  encKeyHex: 'aae74ab4049d24620c02a210afd208ec0350e12d4c7bf0697474479eaad63902',
} as const;

const hex = (b: Uint8Array): string => [...b].map((x) => x.toString(16).padStart(2, '0')).join('');
const bytes = (...v: number[]) => new Uint8Array(v);

// ===========================================================================
// G11 — el módulo cripto importa y expone su API
// ===========================================================================
describe('G11 — crypto.ts compila e importa', () => {
  it('exporta la API cripto esperada', () => {
    expect(CRYPTO_VERSION).toBe(2);
    expect(typeof deriveMasterKey).toBe('function');
    expect(typeof setupUserCrypto).toBe('function');
    expect(typeof encryptEntry).toBe('function');
    expect(typeof encryptFile).toBe('function');
    expect(VaultSession).toBeTypeOf('function');
  });
});

// ===========================================================================
// A8-b — el KDF del cliente es Argon2id con los parámetros anclados
// ===========================================================================
describe('A8-b — KDF Argon2id con KDF_PARAMS', () => {
  it('KDF_PARAMS son los parámetros esperados', () => {
    expect(KDF_PARAMS.algo).toBe('argon2id');
    expect(KDF_PARAMS.m).toBe(65536); // 64 MiB
    expect(KDF_PARAMS.t).toBe(3);
    expect(KDF_PARAMS.p).toBe(4);
    expect(KDF_PARAMS.hashLen).toBe(32);
    expect(KDF_PARAMS.version).toBe(19); // 0x13 = Argon2 v1.3
  });

  it('deriveMasterKey produce 32 bytes', async () => {
    const mk = await deriveMasterKey('pw', generateSalt());
    expect(mk).toBeInstanceOf(Uint8Array);
    expect(mk.length).toBe(32);
  });
});

// ===========================================================================
// Z4 — vector KDF fijo (ancla; compartido con Python de L1)
// ===========================================================================
describe('Z4 — vector KDF fijo', () => {
  it('(password, salt) conocidos → MK/AuthKey/EncKey conocidos', async () => {
    const salt = fromBase64(Z4_VECTOR.saltB64);
    const mk = await deriveMasterKey(Z4_VECTOR.password, salt, KDF_PARAMS);
    expect(hex(mk)).toBe(Z4_VECTOR.mkHex);

    const [authKey, encKey] = await Promise.all([deriveAuthKey(mk), deriveEncKey(mk)]);
    expect(hex(authKey)).toBe(Z4_VECTOR.authKeyHex);
    expect(hex(encKey)).toBe(Z4_VECTOR.encKeyHex);
  });

  it('AuthKey y EncKey son de dominio separado (HKDF info distinto)', async () => {
    const mk = await deriveMasterKey(Z4_VECTOR.password, fromBase64(Z4_VECTOR.saltB64));
    const [a, e] = await Promise.all([deriveAuthKey(mk), deriveEncKey(mk)]);
    expect(hex(a)).not.toBe(hex(e));
  });
});

// ===========================================================================
// Z3 — round-trip de derivación y de wrap/unwrap; determinismo
// ===========================================================================
describe('Z3 — round-trip de derivación', () => {
  it('deriveMasterKey es determinista (mismo pwd+salt → mismo MK)', async () => {
    const salt = generateSalt();
    const a = await deriveMasterKey('una-maestra-larga', salt);
    const b = await deriveMasterKey('una-maestra-larga', salt);
    expect(hex(a)).toBe(hex(b));
  });

  it('salt distinta → MK distinta', async () => {
    const a = await deriveMasterKey('pw', bytes(...Array(16).fill(1)));
    const b = await deriveMasterKey('pw', bytes(...Array(16).fill(2)));
    expect(hex(a)).not.toBe(hex(b));
  });

  it('wrap(EncKey, VaultKey) → unwrap devuelve la VaultKey original', async () => {
    const encKey = randomBytes(32);
    const vaultKeyRaw = generateVaultKey();
    const wrapped = await wrapVaultKey(encKey, vaultKeyRaw);
    const back = await unwrapVaultKey(encKey, wrapped);
    expect(hex(back)).toBe(hex(vaultKeyRaw));
  });

  it('setupUserCrypto → unlockVault reconstruye una VaultKey que descifra la misma entrada', async () => {
    const { setup, vaultKey } = await setupUserCrypto('maestra-de-prueba-12');
    expect(setup.kdfParams).toEqual(KDF_PARAMS);
    expect(setup.cryptoVersion).toBe(CRYPTO_VERSION);

    const aad = buildEntryAAD(7, 42);
    const ct = await encryptEntry(vaultKey, 'secreto', aad);

    const { vaultKey: reVaultKey, authKey } = await unlockVault(
      'maestra-de-prueba-12',
      setup.kdfSalt,
      setup.wrappedVaultKey,
    );
    expect(authKey).toBe(setup.authKey); // la AuthKey re-derivada casa con la del setup
    expect(await decryptEntry(reVaultKey, ct, aad)).toBe('secreto');
  });

  it('unlockVault con maestra incorrecta LANZA (unwrap AES-GCM falla)', async () => {
    const { setup } = await setupUserCrypto('la-maestra-correcta-1');
    await expect(
      unlockVault('otra-maestra-distinta', setup.kdfSalt, setup.wrappedVaultKey),
    ).rejects.toThrow();
  });
});

// ===========================================================================
// Z2 / C6 — AEAD detecta manipulación
// ===========================================================================
describe('Z2 / C6 — AEAD antimanipulación', () => {
  it('voltear un byte del ciphertext → decryptEntry LANZA', async () => {
    const vaultKeyRaw = generateVaultKey();
    const vaultKey = await importVaultKey(vaultKeyRaw);
    const aad = buildEntryAAD(1, 1);
    const ctB64 = await encryptEntry(vaultKey, 'texto-claro-sensible', aad);

    const raw = fromBase64(ctB64);
    // voltea un byte del cuerpo del ciphertext (tras el nonce de 12 bytes)
    const tampered = new Uint8Array(raw);
    tampered[13] ^= 0x01;
    await expect(decryptEntry(vaultKey, toBase64(tampered), aad)).rejects.toThrow();
  });

  it('voltear un byte del TAG (último byte) → decrypt LANZA', async () => {
    const key = await importAesKey(randomBytes(32));
    const blob = await aesGcmEncrypt(key, utf8('hola'));
    const tampered = new Uint8Array(blob);
    tampered[tampered.length - 1] ^= 0x80;
    await expect(aesGcmDecrypt(key, tampered)).rejects.toThrow();
  });

  it('blob demasiado corto → decrypt LANZA con mensaje explícito', async () => {
    const key = await importAesKey(randomBytes(32));
    await expect(aesGcmDecrypt(key, bytes(1, 2, 3))).rejects.toThrow(/demasiado corto/);
  });

  it('un ciphertext intacto SÍ descifra (control negativo)', async () => {
    const key = await importAesKey(randomBytes(32));
    const blob = await aesGcmEncrypt(key, utf8('mensaje'));
    expect(fromUtf8(await aesGcmDecrypt(key, blob))).toBe('mensaje');
  });
});

// ===========================================================================
// Z9 — AAD atada a la identidad (user_id | entry_id | version)
// ===========================================================================
describe('Z9 — AAD atada a la identidad', () => {
  it('cambiar entry_id en la AAD al descifrar → LANZA', async () => {
    const vaultKey = await importVaultKey(generateVaultKey());
    const ct = await encryptEntry(vaultKey, 'valor', buildEntryAAD(10, 1));
    await expect(decryptEntry(vaultKey, ct, buildEntryAAD(10, 2))).rejects.toThrow();
  });

  it('cambiar user_id en la AAD al descifrar → LANZA', async () => {
    const vaultKey = await importVaultKey(generateVaultKey());
    const ct = await encryptEntry(vaultKey, 'valor', buildEntryAAD(10, 1));
    await expect(decryptEntry(vaultKey, ct, buildEntryAAD(99, 1))).rejects.toThrow();
  });

  it('degradar la versión en la AAD → LANZA', async () => {
    const vaultKey = await importVaultKey(generateVaultKey());
    const ct = await encryptEntry(vaultKey, 'valor', buildEntryAAD(10, 1, CRYPTO_VERSION));
    await expect(decryptEntry(vaultKey, ct, buildEntryAAD(10, 1, CRYPTO_VERSION - 1))).rejects.toThrow();
  });

  it('la MISMA AAD descifra (control): un blob en su sitio sí abre', async () => {
    const vaultKey = await importVaultKey(generateVaultKey());
    const aad = buildEntryAAD(10, 1);
    const ct = await encryptEntry(vaultKey, 'valor', aad);
    expect(await decryptEntry(vaultKey, ct, aad)).toBe('valor');
  });

  it('buildEntryAAD codifica user|entry|version en UTF-8', () => {
    expect(fromUtf8(buildEntryAAD(3, 4, 2))).toBe('3|4|2');
  });
});

// ===========================================================================
// Rotación de maestra (M8 / Z10 en su parte cliente): re-envuelve, NO re-cifra
// ===========================================================================
describe('rotateMasterPassword — re-envuelve la VaultKey sin re-cifrar la bóveda', () => {
  it('tras rotar, la NUEVA maestra abre la MISMA entrada cifrada con la VaultKey original', async () => {
    const { setup, vaultKey } = await setupUserCrypto('maestra-vieja-123');
    const aad = buildEntryAAD(1, 1);
    const ct = await encryptEntry(vaultKey, 'no-se-re-cifra', aad); // cifrado con VaultKey original

    const rotated = await rotateMasterPassword(
      'maestra-vieja-123',
      setup.kdfSalt,
      setup.wrappedVaultKey,
      'maestra-nueva-456',
    );
    expect(rotated.currentAuthKey).toBe(setup.authKey); // prueba de posesión de la maestra ACTUAL
    expect(rotated.kdfSalt).not.toBe(setup.kdfSalt); // sal nueva

    const { vaultKey: reKey } = await unlockVault('maestra-nueva-456', rotated.kdfSalt, rotated.wrappedVaultKey);
    expect(await decryptEntry(reKey, ct, aad)).toBe('no-se-re-cifra'); // el ciphertext viejo sigue válido
  });

  it('rotar con la maestra actual incorrecta → LANZA', async () => {
    const { setup } = await setupUserCrypto('maestra-vieja-123');
    await expect(
      rotateMasterPassword('maestra-equivocada', setup.kdfSalt, setup.wrappedVaultKey, 'nueva'),
    ).rejects.toThrow();
  });
});

// ===========================================================================
// Subclave de bóveda privada (A9 / Z11-Z12 en su parte cliente)
// ===========================================================================
describe('setupVaultSubKey / unlockVaultSubKey / rotateVaultPassword', () => {
  it('setup → unlock reconstruye la VaultSubKey que descifra la entrada de la bóveda', async () => {
    const { setup, subKey } = await setupVaultSubKey('password-del-vault-1');
    const aad = buildEntryAAD('u', 'e');
    const ct = await encryptEntry(subKey, 'secreto-privado', aad);

    const { subKey: reSub, subAuthKey } = await unlockVaultSubKey(
      'password-del-vault-1',
      setup.subKdfSalt,
      setup.wrappedVaultSubkey,
    );
    expect(subAuthKey).toBe(setup.subAuthKey);
    expect(await decryptEntry(reSub, ct, aad)).toBe('secreto-privado');
  });

  it('desbloquear con la contraseña del vault incorrecta → LANZA', async () => {
    const { setup } = await setupVaultSubKey('password-del-vault-1');
    await expect(
      unlockVaultSubKey('password-equivocada', setup.subKdfSalt, setup.wrappedVaultSubkey),
    ).rejects.toThrow();
  });

  it('rotar la contraseña del vault re-envuelve la MISMA VaultSubKey', async () => {
    const { setup, subKey } = await setupVaultSubKey('vault-pw-vieja-1');
    const aad = buildEntryAAD('u', 'e');
    const ct = await encryptEntry(subKey, 'contenido', aad);

    const rotated = await rotateVaultPassword('vault-pw-vieja-1', setup.subKdfSalt, setup.wrappedVaultSubkey, 'vault-pw-nueva-2');
    const { subKey: reSub } = await unlockVaultSubKey('vault-pw-nueva-2', rotated.subKdfSalt, rotated.wrappedVaultSubkey);
    expect(await decryptEntry(reSub, ct, aad)).toBe('contenido');
  });
});

// ===========================================================================
// Z13 — cifrado de ficheros por chunks (> 1 MiB), round-trip byte a byte
// ===========================================================================
describe('Z13 — cifrado de ficheros por chunks', () => {
  // Contenido determinista > FILE_CHUNK_SIZE (1 MiB) → fuerza varios chunks con el tamaño real.
  const makeBytes = (n: number): Uint8Array => {
    const b = new Uint8Array(n);
    for (let i = 0; i < n; i++) b[i] = (i * 31 + 7) & 0xff;
    return b;
  };

  it('un fichero > 1 MiB se cifra y descifra byte a byte (FileKey envuelta con VaultKey)', async () => {
    const vaultKey = await importVaultKey(generateVaultKey());
    const fileKeyRaw = generateFileKey();
    const wrapped = await wrapFileKey(vaultKey, fileKeyRaw);
    const reFileKey = await unwrapFileKey(vaultKey, wrapped);
    expect(hex(reFileKey)).toBe(hex(fileKeyRaw));

    const plain = makeBytes(1024 * 1024 * 2 + 12345); // ~2 MiB + resto → 3 chunks
    const source = new Blob([plain]);
    const enc = await encryptFile(fileKeyRaw, source);
    const dec = await decryptFile(fileKeyRaw, enc);
    const back = new Uint8Array(await dec.arrayBuffer());
    expect(back.length).toBe(plain.length);
    expect(hex(back)).toBe(hex(plain));
  });

  it('un fichero pequeño (< 1 MiB, un solo chunk) también round-trips', async () => {
    const fileKeyRaw = generateFileKey();
    const plain = makeBytes(1000);
    const enc = await encryptFile(fileKeyRaw, new Blob([plain]));
    const back = new Uint8Array(await (await decryptFile(fileKeyRaw, enc)).arrayBuffer());
    expect(hex(back)).toBe(hex(plain));
  });

  it('manipular un byte del cuerpo cifrado → decryptFile LANZA (tag GCM)', async () => {
    const fileKeyRaw = generateFileKey();
    const enc = await encryptFile(fileKeyRaw, new Blob([makeBytes(2048)]));
    const encBytes = new Uint8Array(await enc.arrayBuffer());
    encBytes[encBytes.length - 5] ^= 0x01; // dentro del último chunk
    await expect(decryptFile(fileKeyRaw, new Blob([encBytes]))).rejects.toThrow();
  });

  it('cabecera inválida → decryptFile LANZA con mensaje explícito', async () => {
    const fileKeyRaw = generateFileKey();
    const enc = await encryptFile(fileKeyRaw, new Blob([makeBytes(64)]));
    const encBytes = new Uint8Array(await enc.arrayBuffer());
    encBytes[0] ^= 0xff; // rompe el MAGIC
    await expect(decryptFile(fileKeyRaw, new Blob([encBytes]))).rejects.toThrow(/Cabecera/);
  });

  it('reordenar/truncar chunks → decryptFile LANZA (AAD counter||final)', async () => {
    // chunkSize pequeño para forzar múltiples chunks y truncar el último.
    const fileKeyRaw = generateFileKey();
    const chunkSize = 64;
    const enc = await encryptFile(fileKeyRaw, new Blob([makeBytes(64 * 4 + 10)]), chunkSize);
    const encBytes = new Uint8Array(await enc.arrayBuffer());
    // quita el último chunk (y su tag): el descifrador espera el flag final donde ya no está.
    const truncated = encBytes.subarray(0, encBytes.length - (chunkSize + 16));
    await expect(decryptFile(fileKeyRaw, new Blob([truncated]), chunkSize)).rejects.toThrow();
  });
});

// ===========================================================================
// Z14 (FORMA del código) — PUNTO CIEGO declarado
// ===========================================================================
describe('Z14 — wrap/unwrap sin AAD: forma del código (verificación real = L4/navegador)', () => {
  it('wrapVaultKey/unwrapVaultKey funcionan SIN additionalData (round-trip)', async () => {
    // En Node esto pasa igualmente; el punto es que la ruta sin-AAD existe y es la usada al
    // envolver la VaultKey. La regresión real (el navegador lanzaba con additionalData=undefined)
    // sólo se observa en L4.
    const encKey = randomBytes(32);
    const vk = generateVaultKey();
    expect(hex(await unwrapVaultKey(encKey, await wrapVaultKey(encKey, vk)))).toBe(hex(vk));
  });

  it('crypto.ts guarda additionalData sólo si hay AAD (guardián `if (aad !== undefined)`)', () => {
    // Afirmación sobre la FORMA del código: AesGcmParams NO lleva la clave additionalData cuando
    // no hay AAD. Éste es el freno de regresión del bug del 25-jul que el estático de tipos no ve.
    const src = readFileSync(resolve(process.cwd(), 'src/services/crypto.ts'), 'utf8');
    const guards = src.match(/if \(aad !== undefined\) params\.additionalData = aad;/g) ?? [];
    expect(guards.length).toBe(2); // uno en aesGcmEncrypt, otro en aesGcmDecrypt
    // y NO existe ninguna asignación de additionalData sin ese guardián: toda ocurrencia de
    // `params.additionalData = aad` está precedida por `if (aad !== undefined)`.
    const allAssigns = src.match(/params\.additionalData = aad/g) ?? [];
    expect(allAssigns.length).toBe(guards.length);
  });
});

// ===========================================================================
// VaultSession (parte L3 de Z15) — cobertura del estado con reloj inyectable
// ===========================================================================
describe('VaultSession — VaultKey en memoria con auto-bloqueo', () => {
  it('unlock → isUnlocked/getKey; lock la limpia y dispara onLock', async () => {
    const onLock = vi.fn();
    let t = 1000;
    const s = new VaultSession({ idleTimeoutMs: 5000, now: () => t, onLock });
    expect(s.isUnlocked()).toBe(false);

    const key = await importVaultKey(generateVaultKey());
    s.unlock(key);
    expect(s.isUnlocked()).toBe(true);
    expect(s.getKey()).toBe(key);
    expect(s.remainingMs()).toBe(5000);

    s.lock();
    expect(s.isUnlocked()).toBe(false);
    expect(onLock).toHaveBeenCalledTimes(1);
    expect(s.remainingMs()).toBe(0);
    expect(() => s.getKey()).toThrow(/bloqueada/);
  });

  it('expira por inactividad y touch renueva la marca', async () => {
    let t = 0;
    const s = new VaultSession({ idleTimeoutMs: 1000, now: () => t });
    s.unlock(await importVaultKey(generateVaultKey()));
    t = 500;
    s.touch();
    t = 1400; // 900 ms desde el touch < 1000 → sigue viva
    expect(s.isUnlocked()).toBe(true);
    t = 2500; // > 1000 ms desde el último getKey/touch → expira
    expect(s.isUnlocked()).toBe(false);
    expect(() => s.getKey()).toThrow();
  });
});

// ===========================================================================
// Utilidades de codificación (cobertura de base64/utf8/concat)
// ===========================================================================
describe('utilidades de codificación', () => {
  it('toBase64/fromBase64 son inversas', () => {
    const b = randomBytes(40);
    expect(hex(fromBase64(toBase64(b)))).toBe(hex(b));
  });

  it('utf8/fromUtf8 son inversas (incluye no-ASCII)', () => {
    expect(fromUtf8(utf8('áéí€ 🔐'))).toBe('áéí€ 🔐');
  });
});
