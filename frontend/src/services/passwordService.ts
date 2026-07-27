// services/passwordService.ts — Contraseñas zero-knowledge (Fase 2)
//
// El servidor sólo maneja blobs opacos. Aquí se cifra {website, username, password} con la
// VaultKey antes de enviar, y se descifra al recibir. La VaultKey vive en cryptoSession; si la
// bóveda está bloqueada, las operaciones que necesitan cripto lanzan/piden desbloqueo.
import { type PasswordAccount } from '../components/account/AccountCard';
import { type AddPasswordWithVaultData } from '../components/account/AddPasswordModal';
import { cryptoSession, type EntryPayload } from './cryptoSession';
import { masterKeyService } from './masterKeyService';

import { API_BASE_URL } from '../config/api';

export interface UnlockPasswordResponse {
  success: boolean;
  password?: string;
  account?: { id: number; website: string; username: string };
  error?: string;
}

export interface ApiResponse {
  success: boolean;
  error?: string;
  message?: string;
}

class PasswordService {
  private getCSRFToken(): string {
    for (const cookie of document.cookie.split(';')) {
      const [name, value] = cookie.trim().split('=');
      if (name === 'csrftoken') return value;
    }
    return '';
  }

  private async makeRequest(endpoint: string, options: RequestInit = {}): Promise<any> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
    };
    const csrfToken = this.getCSRFToken();
    if (csrfToken) headers['X-CSRFToken'] = csrfToken;

    const response = await fetch(`${API_BASE_URL}${endpoint}`, {
      ...options,
      headers: { ...headers, ...options.headers },
      credentials: 'include',
    });

    if (!response.ok) {
      if (response.status === 401) {
        window.dispatchEvent(new CustomEvent('auth:sessionExpired'));
        throw new Error('Sesión expirada. Por favor, inicia sesión nuevamente.');
      }
      const errorData = await response.json().catch(() => ({}));
      throw new Error(errorData.error || `Error ${response.status}: ${response.statusText}`);
    }

    return response.json();
  }

  /** Descifra un blob opaco del servidor en un PasswordAccount para la UI. */
  private async toAccount(entry: any): Promise<PasswordAccount | null> {
    if (!entry.ciphertext || !entry.client_id) {
      // Registro legacy (v1) o incompleto: se ignora aquí; lo trata el asistente del paso 26.
      return null;
    }
    try {
      // Elige la clave por la bóveda de la entrada: VaultSubKey si es una bóveda privada
      // desbloqueada, VaultKey principal en caso contrario (paso 24).
      const payload = await cryptoSession.decryptEntryForVault(
        entry.client_id,
        entry.ciphertext,
        entry.crypto_version,
        entry.vault_id ?? null,
      );
      return {
        id: entry.id,
        website: payload.website,
        username: payload.username,
        decrypted_password: payload.password,
        // Metadatos no sensibles para el análisis de seguridad en cliente (paso 27):
        created_at: entry.created_at,
        updated_at: entry.updated_at,
        // Campos del esquema legado, ya no provienen del servidor:
        encrypted_password: '',
        encryption_algorithm: '',
        salt: '',
        iv_or_nonce: '',
        encrypted_key: '',
        vault_id: entry.vault_id ?? null,
      };
    } catch (error) {
      console.warn(`No se pudo descifrar la entrada ${entry.id}:`, error);
      return null;
    }
  }

  /** Obtener todas las cuentas del usuario (descifradas en cliente). */
  async getAccounts(vaultId?: number | string | null): Promise<PasswordAccount[]> {
    const data = await this.makeRequest('/api/accounts/');
    const raw: any[] = data.accounts || [];

    const accounts: PasswordAccount[] = [];
    for (const entry of raw) {
      const acc = await this.toAccount(entry);
      if (acc) accounts.push(acc);
    }

    if (vaultId === undefined) return accounts;
    if (vaultId === null || vaultId === 'unvaulted') {
      return accounts.filter((a) => a.vault_id == null);
    }
    const vid = Number(vaultId);
    return accounts.filter((a) => a.vault_id === vid);
  }

  async getAccountsWithVaults(vaultId?: number | string | null): Promise<PasswordAccount[]> {
    return this.getAccounts(vaultId);
  }

  /**
   * Descifra en cliente una lista de blobs opacos del servidor (los que devuelven endpoints como
   * `/api/vaults/<id>/passwords/`) en PasswordAccount para la UI. Las entradas que no se pueden
   * descifrar (bóveda bloqueada, registro legacy) se omiten sin romper el resto.
   */
  async decryptEntries(rawEntries: any[]): Promise<PasswordAccount[]> {
    const accounts: PasswordAccount[] = [];
    for (const entry of rawEntries || []) {
      const acc = await this.toAccount(entry);
      if (acc) accounts.push(acc);
    }
    return accounts;
  }

  /** Crear una cuenta: cifra {website, username, password} y envía el blob opaco. */
  async createAccount(accountData: AddPasswordWithVaultData): Promise<ApiResponse> {
    try {
      if (!cryptoSession.isUnlocked()) {
        return { success: false, error: 'La bóveda está bloqueada. Desbloquéala primero.' };
      }

      const cleanWebsite = accountData.website
        .replace(/^https?:\/\//, '')
        .replace(/^www\./, '');

      const vaultId = accountData.vault_id ?? null;
      const clientId = cryptoSession.newClientId();
      const payload: EntryPayload = {
        website: cleanWebsite,
        username: accountData.username,
        password: accountData.password,
      };
      // Bóveda privada desbloqueada → se cifra bajo su VaultSubKey; si no, bajo la principal.
      const ciphertext = await cryptoSession.encryptEntryForVault(clientId, payload, vaultId);

      const data = await this.makeRequest('/api/passwords/add/', {
        method: 'POST',
        body: JSON.stringify({
          client_id: clientId,
          ciphertext,
          crypto_version: 2,
          vault_id: vaultId,
        }),
      });

      return { success: data.success, message: data.message || 'Contraseña creada exitosamente' };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Error de conexión al crear la contraseña',
      };
    }
  }

  /**
   * Revelar la contraseña de una cuenta. Con la bóveda desbloqueada es una operación local;
   * si estuviera bloqueada y se pasa la maestra, se desbloquea antes.
   */
  async unlockPassword(passwordId: number, masterPassword: string): Promise<UnlockPasswordResponse> {
    try {
      if (!cryptoSession.isUnlocked()) {
        const unlock = await masterKeyService.verifyMasterKey(masterPassword);
        if (!unlock.success) return { success: false, error: unlock.error };
      }

      const accounts = await this.getAccounts();
      const account = accounts.find((a) => a.id === passwordId);
      if (!account) return { success: false, error: 'Contraseña no encontrada' };

      return {
        success: true,
        password: account.decrypted_password,
        account: { id: account.id, website: account.website, username: account.username },
      };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Error al desbloquear la contraseña',
      };
    }
  }

  /** Eliminar una contraseña. Sin contraseña maestra: autorizado por la sesión. */
  async deletePassword(passwordId: number, _masterPassword?: string): Promise<ApiResponse> {
    try {
      const data = await this.makeRequest(`/api/passwords/${passwordId}/delete/`, {
        method: 'POST',
        body: JSON.stringify({}),
      });
      return { success: data.success, message: data.message, error: data.error };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Error al eliminar la contraseña',
      };
    }
  }

  /** Actualizar una contraseña: re-cifra el blob con los datos nuevos. */
  async updatePassword(
    passwordId: number,
    accountData: Partial<AddPasswordWithVaultData>,
    _masterPassword?: string,
  ): Promise<ApiResponse> {
    try {
      if (!cryptoSession.isUnlocked()) {
        return { success: false, error: 'La bóveda está bloqueada. Desbloquéala primero.' };
      }

      // Se re-cifra el registro completo; el cliente debe aportar los tres campos.
      const cleanWebsite = (accountData.website || '')
        .replace(/^https?:\/\//, '')
        .replace(/^www\./, '');

      // La bóveda ACTUAL de la entrada decide la clave (no se confía en lo que pase el llamador):
      // se consulta al servidor. Si la entrada está en una privada, ésta estará desbloqueada
      // (la estamos editando), así que aparece en /api/accounts/.
      const raw = await this.makeRequest('/api/accounts/');
      const current = (raw.accounts || []).find((e: any) => e.id === passwordId);
      const vaultId = current ? (current.vault_id ?? null) : (accountData.vault_id ?? null);

      const clientId = cryptoSession.newClientId();
      const payload: EntryPayload = {
        website: cleanWebsite,
        username: accountData.username || '',
        password: accountData.password || '',
      };
      const ciphertext = await cryptoSession.encryptEntryForVault(clientId, payload, vaultId);

      const data = await this.makeRequest(`/api/passwords/${passwordId}/update/`, {
        method: 'POST',
        body: JSON.stringify({ ciphertext, crypto_version: 2, client_id: clientId }),
      });

      return { success: data.success, message: data.message || 'Contraseña actualizada exitosamente' };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Error de conexión al actualizar la contraseña',
      };
    }
  }

  /**
   * Re-cifra una entrada para un movimiento que cambia de dominio de clave (paso 24b): la descifra
   * bajo la clave de su bóveda actual y la vuelve a cifrar bajo la del destino, conservando el
   * mismo client_id (la AAD no cambia). Devuelve el ciphertext nuevo, o null si el movimiento no
   * cambia de dominio (mismo caso: el servidor no necesita blob nuevo).
   *
   * `entry` es el blob crudo del servidor { id, client_id, ciphertext, crypto_version, vault_id }.
   */
  private async reencryptForMove(entry: any, destVaultId: number | null): Promise<string | null> {
    const sourceVid: number | null = entry.vault_id ?? null;
    if (cryptoSession.keyDomainId(sourceVid) === cryptoSession.keyDomainId(destVaultId)) return null;
    if (!entry.client_id || !entry.ciphertext) return null; // legacy/incompleto: lo rechaza el servidor
    const payload = await cryptoSession.decryptEntryForVault(
      entry.client_id, entry.ciphertext, entry.crypto_version, sourceVid,
    );
    return cryptoSession.encryptEntryForVault(entry.client_id, payload, destVaultId);
  }

  /** Mover una contraseña a un vault. Si cambia el dominio de clave (entra/sale de una privada),
   *  re-cifra el blob antes de enviarlo (paso 24b). */
  async movePasswordToVault(
    passwordId: number,
    vaultId: number | null,
    _vaultPassword?: string,
  ): Promise<ApiResponse> {
    try {
      const body: Record<string, any> = { password_id: passwordId, vault_id: vaultId };

      // Necesitamos el blob de origen para saber si cambia de dominio y, si cambia, re-cifrarlo.
      const raw = await this.makeRequest('/api/accounts/');
      const entry = (raw.accounts || []).find((e: any) => e.id === passwordId);
      if (entry) {
        const newCiphertext = await this.reencryptForMove(entry, vaultId ?? null);
        if (newCiphertext) body.ciphertext = newCiphertext;
      }

      const data = await this.makeRequest('/api/passwords/move/', {
        method: 'POST',
        body: JSON.stringify(body),
      });
      return { success: data.success, message: data.message, error: data.error };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Error al mover la contraseña',
      };
    }
  }

  async batchMovePasswords(
    passwordIds: number[],
    destinationVaultId: number | null,
    _vaultPassword?: string,
  ): Promise<ApiResponse> {
    try {
      const dest = destinationVaultId ?? null;

      // Re-cifrar (sólo) las entradas que cambian de dominio de clave.
      const raw = await this.makeRequest('/api/accounts/');
      const byId = new Map<number, any>((raw.accounts || []).map((e: any) => [e.id, e]));
      const ciphertexts: Record<string, string> = {};
      for (const id of passwordIds) {
        const entry = byId.get(id);
        if (!entry) continue;
        const newCiphertext = await this.reencryptForMove(entry, dest);
        if (newCiphertext) ciphertexts[String(id)] = newCiphertext;
      }

      const body: Record<string, any> = {
        password_ids: passwordIds,
        destination_vault_id: destinationVaultId,
      };
      if (Object.keys(ciphertexts).length) body.ciphertexts = ciphertexts;

      const data = await this.makeRequest('/api/batch-move-passwords/', {
        method: 'POST',
        body: JSON.stringify(body),
      });
      return { success: data.success, message: data.message, error: data.error };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Error al mover las contraseñas',
      };
    }
  }

  /** Revelar todas las contraseñas (con la bóveda desbloqueada). */
  async unlockAllPasswords(masterPassword: string): Promise<{
    success: boolean;
    accounts?: PasswordAccount[];
    error?: string;
  }> {
    try {
      if (!cryptoSession.isUnlocked()) {
        const unlock = await masterKeyService.verifyMasterKey(masterPassword);
        if (!unlock.success) return { success: false, error: unlock.error };
      }
      const accounts = await this.getAccounts();
      return { success: true, accounts };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Error al desbloquear las contraseñas',
      };
    }
  }

  /**
   * Generador del servidor (secrets.randbelow). Se conserva como passthrough; el generador
   * real de la UI es el del cliente (PasswordGeneratorPage, crypto.getRandomValues).
   */
  async generatePasswords(
    count: number = 5,
    length: number = 20,
    useSpecial: boolean = true,
    useNumbers: boolean = true,
  ): Promise<{ success: boolean; passwords?: string[]; error?: string }> {
    try {
      const params = new URLSearchParams({
        count: String(count),
        length: String(length),
        special: String(useSpecial),
        numbers: String(useNumbers),
      });
      const data = await this.makeRequest(`/api/password-generator/?${params}`);
      return { success: true, passwords: data.passwords };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Error al generar contraseñas',
      };
    }
  }

  /** Eliminar varias contraseñas. Sin contraseña maestra: autorizado por la sesión. */
  async batchDeletePasswords(passwordIds: number[], _masterPassword?: string): Promise<ApiResponse> {
    try {
      const data = await this.makeRequest('/api/batch-delete-passwords/', {
        method: 'POST',
        body: JSON.stringify({ password_ids: passwordIds }),
      });
      return { success: data.success, message: data.message, error: data.error };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Error al eliminar las contraseñas',
      };
    }
  }
}

export const passwordService = new PasswordService();
