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
      const payload = await cryptoSession.decryptEntry(
        entry.client_id,
        entry.ciphertext,
        entry.crypto_version,
      );
      return {
        id: entry.id,
        website: payload.website,
        username: payload.username,
        decrypted_password: payload.password,
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

  /** Crear una cuenta: cifra {website, username, password} y envía el blob opaco. */
  async createAccount(accountData: AddPasswordWithVaultData): Promise<ApiResponse> {
    try {
      if (!cryptoSession.isUnlocked()) {
        return { success: false, error: 'La bóveda está bloqueada. Desbloquéala primero.' };
      }

      const cleanWebsite = accountData.website
        .replace(/^https?:\/\//, '')
        .replace(/^www\./, '');

      const clientId = cryptoSession.newClientId();
      const payload: EntryPayload = {
        website: cleanWebsite,
        username: accountData.username,
        password: accountData.password,
      };
      const ciphertext = await cryptoSession.encryptEntry(clientId, payload);

      const data = await this.makeRequest('/api/passwords/add/', {
        method: 'POST',
        body: JSON.stringify({
          client_id: clientId,
          ciphertext,
          crypto_version: 2,
          vault_id: accountData.vault_id || null,
          vault_password: accountData.vault_password || '',
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

      const clientId = cryptoSession.newClientId();
      const payload: EntryPayload = {
        website: cleanWebsite,
        username: accountData.username || '',
        password: accountData.password || '',
      };
      const ciphertext = await cryptoSession.encryptEntry(clientId, payload);

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

  /** Mover una contraseña a un vault (sin cripto; el blob no cambia). */
  async movePasswordToVault(
    passwordId: number,
    vaultId: number | null,
    vaultPassword?: string,
  ): Promise<ApiResponse> {
    try {
      const data = await this.makeRequest('/api/passwords/move/', {
        method: 'POST',
        body: JSON.stringify({ password_id: passwordId, vault_id: vaultId, vault_password: vaultPassword }),
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
    vaultPassword?: string,
  ): Promise<ApiResponse> {
    try {
      const data = await this.makeRequest('/api/batch-move-passwords/', {
        method: 'POST',
        body: JSON.stringify({
          password_ids: passwordIds,
          destination_vault_id: destinationVaultId,
          vault_password: vaultPassword,
        }),
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
