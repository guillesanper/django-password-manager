// services/masterKeyService.ts — Clave maestra zero-knowledge (Fase 2)
//
// La contraseña maestra NUNCA sale del navegador. Aquí se deriva todo con crypto.ts:
//   - setMasterKey: genera el material (setupUserCrypto) y lo envía al servidor.
//   - verifyMasterKey: DESBLOQUEA la bóveda en local (deriva MK, desenvuelve la VaultKey) y la
//     deja en cryptoSession. Que la desenvoltura no lance es la prueba de que la maestra es
//     correcta; el servidor nunca la ve.
//   - lock: borra la VaultKey de memoria.

import { authService } from './authService';
import { API_BASE_URL } from '../config/api';
import { cryptoSession } from './cryptoSession';
import { setupUserCrypto, unlockVault, type KdfParams } from './crypto';

export interface MasterKeyResponse {
  success: boolean;
  error?: string;
  message?: string;
}

interface CryptoParams {
  kdf_salt: string;
  kdf_params: KdfParams;
  wrapped_vault_key: string;
  crypto_version: number;
}

class MasterKeyService {
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

  private currentUserId(): number {
    const user = authService.getCurrentUser();
    if (!user) throw new Error('No hay usuario autenticado');
    return user.id;
  }

  /**
   * Configura la clave maestra por primera vez: genera salt/MK/AuthKey/EncKey/VaultKey en local,
   * envía al servidor sólo material opaco y deja la bóveda desbloqueada.
   */
  async setMasterKey(masterKey: string): Promise<MasterKeyResponse> {
    try {
      const { setup, vaultKey } = await setupUserCrypto(masterKey);

      const data = await this.makeRequest('/api/master-key/setup/', {
        method: 'POST',
        body: JSON.stringify({
          kdf_salt: setup.kdfSalt,
          kdf_params: setup.kdfParams,
          auth_key: setup.authKey,
          wrapped_vault_key: setup.wrappedVaultKey,
          crypto_version: setup.cryptoVersion,
        }),
      });

      if (data.success) {
        cryptoSession.unlock(vaultKey, this.currentUserId());
      }
      return data;
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Error al configurar la clave maestra',
      };
    }
  }

  /** Indica si el usuario ya tiene material criptográfico configurado. */
  async hasMasterKey(): Promise<{ success: boolean; hasMasterKey: boolean; error?: string }> {
    try {
      const response = await this.makeRequest('/api/master-key/check/', { method: 'GET' });
      return { success: !!response.success, hasMasterKey: !!response.hasMasterKey };
    } catch {
      return { success: false, hasMasterKey: false, error: 'Error al verificar la clave maestra' };
    }
  }

  /**
   * Verifica la clave maestra DESBLOQUEANDO la bóveda en local: pide el material al servidor,
   * deriva la MK y desenvuelve la VaultKey. Si la maestra es incorrecta, la desenvoltura lanza.
   * Deja la VaultKey en cryptoSession para el resto de la sesión.
   */
  async verifyMasterKey(masterKey: string): Promise<MasterKeyResponse> {
    try {
      const params = (await this.makeRequest('/api/master-key/params/', {
        method: 'GET',
      })) as CryptoParams & { success: boolean };

      const { vaultKey } = await unlockVault(
        masterKey,
        params.kdf_salt,
        params.wrapped_vault_key,
        params.kdf_params,
      );

      cryptoSession.unlock(vaultKey, this.currentUserId());
      return { success: true, message: 'Bóveda desbloqueada' };
    } catch (error) {
      // La desenvoltura AES-GCM lanza si la maestra es incorrecta o el blob está manipulado.
      return {
        success: false,
        error: error instanceof Error && error.message.includes('Sesión')
          ? error.message
          : 'Contraseña maestra incorrecta',
      };
    }
  }

  /** Alias explícito de verifyMasterKey para los flujos que hablan de "desbloquear". */
  unlock(masterKey: string): Promise<MasterKeyResponse> {
    return this.verifyMasterKey(masterKey);
  }

  /** Bloquea la bóveda (borra la VaultKey de memoria). */
  lock(): void {
    cryptoSession.lock();
  }

  isUnlocked(): boolean {
    return cryptoSession.isUnlocked();
  }

  /**
   * Cambio de clave maestra. La rotación completa (re-envolver la VaultKey en cliente) es el
   * paso 25; hoy el endpoint responde 501.
   */
  async changeMasterKey(_currentKey: string, _newKey: string): Promise<MasterKeyResponse> {
    return this.makeRequest('/api/master-key/change/', {
      method: 'POST',
      body: JSON.stringify({}),
    }).catch((error) => ({
      success: false,
      error: error instanceof Error ? error.message : 'Cambio de clave maestra no disponible',
    }));
  }
}

export const masterKeyService = new MasterKeyService();
