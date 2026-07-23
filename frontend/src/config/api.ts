/**
 * Origen único de la URL base de la API.
 *
 * Antes cada servicio llevaba `http://localhost:8000` escrito a mano (8 copias),
 * lo que obligaba a publicar el puerto 8000 del contenedor `web` y hacía que
 * cualquier cambio de rutas o de esquema hubiera que replicarlo ocho veces.
 *
 * - En desarrollo (`vite dev` en :5174) apunta al backend en :8000, igual que antes.
 * - En build, cadena vacía: las peticiones salen relativas al origen que sirve la
 *   SPA, que es nginx. Eso es lo que permite cerrar el puerto 8000 y lo que hará
 *   que las cookies `HttpOnly` del paso 8 sean same-origin.
 * - `VITE_API_URL` sobreescribe ambos casos.
 */
const fromEnv = import.meta.env.VITE_API_URL as string | undefined;

export const API_BASE_URL = (
  fromEnv ?? (import.meta.env.DEV ? 'http://localhost:8000' : '')
).replace(/\/$/, '');

export default API_BASE_URL;
