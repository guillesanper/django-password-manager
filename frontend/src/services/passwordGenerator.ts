// Generación de contraseñas con CSPRNG (crypto.getRandomValues), sin sesgo de módulo.
// Funciones puras y testeables: no tocan el DOM ni el estado de React.

// Entero uniforme en [0, maxExclusive) con rejection sampling sobre 32 bits.
// Descarta la cola no divisible por maxExclusive para que todos los valores sean equiprobables.
export function cryptoRandomInt(maxExclusive: number): number {
  if (maxExclusive <= 1) return 0;
  const limit = Math.floor(0x100000000 / maxExclusive) * maxExclusive;
  const buffer = new Uint32Array(1);
  let value: number;
  do {
    crypto.getRandomValues(buffer);
    value = buffer[0];
  } while (value >= limit);
  return value % maxExclusive;
}

// Muestreo uniforme de caracteres con CSPRNG, sin sesgo de módulo.
// Rejection sampling: se descartan los bytes de la cola no divisible por el tamaño del
// alfabeto para que todos los caracteres sean equiprobables.
export function generateFromCharset(charset: string, length: number): string {
  const n = charset.length;
  if (n === 0 || length <= 0) return '';
  // Mayor múltiplo de n que cabe en un byte; bytes >= limit se rechazan.
  const limit = Math.floor(256 / n) * n;
  let password = '';
  const buffer = new Uint8Array(Math.max(length, 16));
  while (password.length < length) {
    crypto.getRandomValues(buffer);
    for (let i = 0; i < buffer.length && password.length < length; i++) {
      const byte = buffer[i];
      if (byte < limit) {
        password += charset.charAt(byte % n);
      }
    }
  }
  return password;
}

const LOWERCASE = 'abcdefghijklmnopqrstuvwxyz';
const UPPERCASE = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const NUMBERS = '0123456789';
const SYMBOLS = '!@#$%^&*()_+-=[]{}|;:,.<>?';

// Contraseña que garantiza al menos un carácter de cada categoría (minúscula, mayúscula,
// número, símbolo), rellena el resto del alfabeto completo y baraja con un Fisher-Yates
// insesgado sobre CSPRNG. Si length < 4 no cabe una de cada categoría: muestrea sin garantía.
export function generateStrongPassword(length = 16): string {
  const categories = [LOWERCASE, UPPERCASE, NUMBERS, SYMBOLS];
  const all = LOWERCASE + UPPERCASE + NUMBERS + SYMBOLS;
  if (length < categories.length) {
    return generateFromCharset(all, length);
  }
  const chars = categories.map((set) => generateFromCharset(set, 1));
  for (let i = chars.length; i < length; i++) {
    chars.push(generateFromCharset(all, 1));
  }
  // Fisher-Yates insesgado (CSPRNG), en lugar del .sort(() => Math.random() - 0.5) sesgado.
  for (let i = chars.length - 1; i > 0; i--) {
    const j = cryptoRandomInt(i + 1);
    [chars[i], chars[j]] = [chars[j], chars[i]];
  }
  return chars.join('');
}
