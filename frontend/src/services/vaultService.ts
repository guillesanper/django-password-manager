// services/vaultService.ts - Servicio para manejar operaciones de vaults
import { authService } from './authService'

import { API_BASE_URL } from '../config/api';
import { cryptoSession } from './cryptoSession';
import { passwordService } from './passwordService';
import { masterKeyService } from './masterKeyService';
import { setupVaultSubKey, unlockVaultSubKey, rotateVaultPassword } from './crypto';

export const VAULT_COLORS = {
  blue: { bg: 'bg-blue-100', text: 'text-blue-800', icon: 'text-blue-600', border: 'border-blue-200' },
  green: { bg: 'bg-green-100', text: 'text-green-800', icon: 'text-green-600', border: 'border-green-200' },
  purple: { bg: 'bg-purple-100', text: 'text-purple-800', icon: 'text-purple-600', border: 'border-purple-200' },
  pink: { bg: 'bg-pink-100', text: 'text-pink-800', icon: 'text-pink-600', border: 'border-pink-200' },
  yellow: { bg: 'bg-yellow-100', text: 'text-yellow-800', icon: 'text-yellow-600', border: 'border-yellow-200' },
  red: { bg: 'bg-red-100', text: 'text-red-800', icon: 'text-red-600', border: 'border-red-200' },
  gray: { bg: 'bg-gray-100', text: 'text-gray-800', icon: 'text-gray-600', border: 'border-gray-200' }
};

export interface CreateVaultData {
  name: string;
  description?: string;
  color: 'blue' | 'green' | 'purple' | 'pink' | 'yellow' | 'red' | 'gray';
  is_private: boolean;
  vault_password?: string;
}

export interface Vault {
  id: number;
  name: string;
  description?: string;
  color: 'blue' | 'green' | 'purple' | 'pink' | 'yellow' | 'red' | 'gray';
  is_private: boolean;
  password_count: number;
  created_at: string;
  updated_at: string;
}

export interface UpdateVaultData {
  name?: string;
  description?: string;
  color?: 'blue' | 'green' | 'purple' | 'pink' | 'yellow' | 'red' | 'gray';
}

export interface VaultStats {
  total_vaults: number;
  private_vaults: number;
  public_vaults: number;
  total_passwords: number;
  unvaulted_passwords: number;
  vaulted_passwords: number;
  vault_colors_used: string[];
  largest_vault: { vault_name: string; password_count: number } | null;
  most_used_color: string | null;
}

export interface ApiResponse<T = any> {
  success: boolean;
  error?: string;
  message?: string;
  data?: T;
}

class VaultService {
  private async getAuthHeaders(): Promise<Record<string, string>> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
    };

    // Obtener token JWT
    const token = authService.getAccessToken();
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }

    // Obtener CSRF token
    const csrfToken = this.getCSRFToken();
    if (csrfToken) {
      headers['X-CSRFToken'] = csrfToken;
    }

    return headers;
  }

  private getCSRFToken(): string {
    const cookies = document.cookie.split(';');
    for (let cookie of cookies) {
      const [name, value] = cookie.trim().split('=');
      if (name === 'csrftoken') {
        return value;
      }
    }
    return '';
  }

  private async makeRequest(endpoint: string, options: RequestInit = {}): Promise<any> {
    try {
      const headers = await this.getAuthHeaders();
      
      const response = await fetch(`${API_BASE_URL}${endpoint}`, {
        ...options,
        headers: {
          ...headers,
          ...options.headers,
        },
        credentials: 'include',
      });

      if (!response.ok) {
        if (response.status === 401) {
          // Token expirado o inválido
          console.error('Autenticación requerida');
          window.dispatchEvent(new CustomEvent('auth:sessionExpired'));
          throw new Error('Sesión expirada. Por favor, inicia sesión nuevamente.');
        }

        const errorData = await response.json().catch(() => ({}));
        const err = new Error(errorData.error || `Error ${response.status}: ${response.statusText}`);
        // Propaga el código de negocio del backend (p. ej. VAULT_LOCKED) para que quien llama pueda
        // distinguir un error fatal de un estado esperable (bóveda bloqueada → pedir contraseña).
        (err as Error & { code?: string }).code = errorData.code;
        throw err;
      }

      return await response.json();
    } catch (error) {
      console.error('Dashboard Service Error:', error);
      throw error;
    }
  }

  /**
   * Obtener todos los vaults del usuario
   */
  async getVaults(): Promise<{ vaults: Vault[]; unvaulted_passwords: number }> {
    try {
      const data = await this.makeRequest('/api/vaults/');
      return {
        vaults: data.vaults || [],
        unvaulted_passwords: data.unvaulted_passwords || 0
      };
    } catch (error) {
      console.error('Error fetching vaults:', error);
      throw new Error('Error al cargar los vaults');
    }
  }

  /**
   * Crear un nuevo vault
   */
  async createVault(vaultData: CreateVaultData): Promise<ApiResponse<Vault>> {
    try {
      // Para bóvedas privadas se deriva el material de subclave en local a partir de la
      // contraseña del vault (zero-knowledge, paso 24); al servidor sólo va material opaco.
      const body: Record<string, any> = {
        name: vaultData.name,
        description: vaultData.description,
        color: vaultData.color,
        is_private: vaultData.is_private,
      };
      let pendingSubKey: CryptoKey | null = null;

      if (vaultData.is_private) {
        if (!vaultData.vault_password) {
          return { success: false, error: 'La bóveda privada requiere una contraseña' };
        }
        const { setup, subKey } = await setupVaultSubKey(vaultData.vault_password);
        body.sub_kdf_salt = setup.subKdfSalt;
        body.sub_kdf_params = setup.subKdfParams;
        body.sub_auth_key = setup.subAuthKey;
        body.wrapped_vault_subkey = setup.wrappedVaultSubkey;
        body.crypto_version = setup.cryptoVersion;
        pendingSubKey = subKey;
      }

      const data = await this.makeRequest('/api/vaults/create/', {
        method: 'POST',
        body: JSON.stringify(body)
      });

      // El servidor deja la bóveda recién creada desbloqueada; se registra su VaultSubKey en
      // memoria para poder cifrar entradas de inmediato.
      if (data.success && pendingSubKey && data.vault?.id != null) {
        cryptoSession.unlockVaultKey(data.vault.id, pendingSubKey);
      }

      return {
        success: data.success,
        message: data.message,
        data: data.vault,
        error: data.error
      };
    } catch (error) {
      console.error('Error creating vault:', error);
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Error al crear el vault'
      };
    }
  }

  /**
   * Actualizar un vault existente
   */
  async updateVault(vaultId: number, vaultData: UpdateVaultData): Promise<ApiResponse<Vault>> {
    try {
      const data = await this.makeRequest(`/api/vaults/${vaultId}/`, {
        method: 'POST',
        body: JSON.stringify(vaultData)
      });

      return {
        success: data.success,
        message: data.message,
        data: data.vault,
        error: data.error
      };
    } catch (error) {
      console.error('Error updating vault:', error);
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Error al actualizar el vault'
      };
    }
  }

  /**
   * Eliminar un vault (autorización zero-knowledge, paso 25).
   *
   * La maestra ya no viaja en claro: se prueba posesión con la AuthKey derivada en local
   * (`deriveAuthProof`). Si la bóveda es privada v2, mover su contenido cambia de dominio de clave,
   * así que se re-cifra cada entrada bajo la clave del destino y se envía en `ciphertexts` (la
   * bóveda debe estar desbloqueada para poder leerla).
   */
  async deleteVault(
    vaultId: number,
    masterPassword: string,
    movePasswordsToVault?: number
  ): Promise<ApiResponse> {
    try {
      let authKey: string;
      try {
        authKey = await masterKeyService.deriveAuthProof(masterPassword);
      } catch {
        return { success: false, error: 'Contraseña maestra incorrecta' };
      }

      const body: Record<string, unknown> = {
        auth_key: authKey,
        move_passwords_to_vault: movePasswordsToVault,
      };

      // ¿Es privada v2? crypto-params responde 200 sólo en ese caso. Si lo es, su contenido está
      // cifrado bajo la VaultSubKey y hay que re-cifrarlo para el dominio del destino.
      const cp = await this.makeRequest(`/api/vaults/${vaultId}/crypto-params/`).catch(() => ({ success: false }));
      if (cp.success) {
        if (!cryptoSession.hasVaultKey(vaultId)) {
          return { success: false, error: 'Desbloquea la bóveda antes de eliminarla.' };
        }
        const listing = await this.makeRequest(`/api/vaults/${vaultId}/passwords/`);
        if (!listing.success) {
          return { success: false, error: listing.error || 'No se pudieron leer las contraseñas de la bóveda' };
        }
        const entries: any[] = listing.passwords || [];
        const destId = movePasswordsToVault ?? null;
        const ciphertexts: Record<string, string> = {};
        for (const e of entries) {
          const payload = await cryptoSession.decryptEntryForVault(e.client_id, e.ciphertext, e.crypto_version, vaultId);
          ciphertexts[String(e.id)] = await cryptoSession.encryptEntryForVault(e.client_id, payload, destId);
        }
        body.ciphertexts = ciphertexts;
      }

      const data = await this.makeRequest(`/api/vaults/${vaultId}/delete/`, {
        method: 'POST',
        body: JSON.stringify(body),
      });

      return {
        success: data.success,
        message: data.message,
        error: data.error
      };
    } catch (error) {
      console.error('Error deleting vault:', error);
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Error al eliminar el vault'
      };
    }
  }

  /**
   * Desbloquear un vault privado
   */
  async unlockVault(vaultId: number, vaultPassword: string): Promise<ApiResponse> {
    try {
      // 1) Material de la bóveda (opaco sin la contraseña del vault).
      const params = await this.makeRequest(`/api/vaults/${vaultId}/crypto-params/`);
      if (!params.success) {
        return { success: false, error: params.error || 'No se pudo obtener el material de la bóveda' };
      }

      // 2) Derivar la VaultSubKey en local; si la contraseña es incorrecta, la desenvoltura lanza.
      let subKey: CryptoKey;
      let subAuthKey: string;
      try {
        ({ subKey, subAuthKey } = await unlockVaultSubKey(
          vaultPassword,
          params.sub_kdf_salt,
          params.wrapped_vault_subkey,
          params.sub_kdf_params,
        ));
      } catch {
        return { success: false, error: 'Contraseña del vault incorrecta' };
      }

      // 3) Probar posesión al servidor (fija el marcador de desbloqueo con TTL).
      const data = await this.makeRequest(`/api/vaults/${vaultId}/unlock/`, {
        method: 'POST',
        body: JSON.stringify({ sub_auth_key: subAuthKey })
      });

      if (data.success) {
        cryptoSession.unlockVaultKey(vaultId, subKey);
      }

      return {
        success: data.success,
        message: data.message,
        error: data.error
      };
    } catch (error) {
      console.error('Error unlocking vault:', error);
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Error al desbloquear el vault'
      };
    }
  }

  /**
   * Obtener contraseñas de un vault específico
   */
  async getVaultPasswords(vaultId: number): Promise<{
    success: boolean;
    vault?: Vault;
    passwords?: any[];
    count?: number;
    error?: string;
    code?: string;
  }> {
    try {
      const data = await this.makeRequest(`/api/vaults/${vaultId}/passwords/`);
      return {
        success: data.success,
        vault: data.vault,
        passwords: data.passwords,
        count: data.count,
        error: data.error
      };
    } catch (error) {
      console.error('Error fetching vault passwords:', error);
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Error al cargar las contraseñas del vault',
        code: (error as { code?: string })?.code,
      };
    }
  }

  /**
   * Obtener contraseñas sin vault
   */
  async getUnvaultedPasswords(): Promise<{
    success: boolean;
    passwords?: any[];
    count?: number;
    error?: string;
  }> {
    try {
      const data = await this.makeRequest('/api/passwords/unvaulted/');
      return {
        success: data.success,
        passwords: data.passwords,
        count: data.count,
        error: data.error
      };
    } catch (error) {
      console.error('Error fetching unvaulted passwords:', error);
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Error al cargar las contraseñas sin vault'
      };
    }
  }

  /**
   * Mover una contraseña a un vault diferente. Delega en passwordService, que es quien tiene la
   * VaultKey/VaultSubKey y re-cifra el blob si el movimiento cambia de dominio de clave (paso 24b).
   */
  async movePasswordToVault(
    passwordId: number,
    vaultId: number | null,
    vaultPassword?: string
  ): Promise<ApiResponse> {
    return passwordService.movePasswordToVault(passwordId, vaultId, vaultPassword);
  }

  /**
   * Mover múltiples contraseñas a un vault. Delega en passwordService (re-cifra las que cambian de
   * dominio de clave). Antes apuntaba a `/api/vaults/batch-move-passwords/`, que no existe.
   */
  async batchMovePasswords(
    passwordIds: number[],
    destinationVaultId: number | null,
    vaultPassword?: string
  ): Promise<ApiResponse> {
    return passwordService.batchMovePasswords(passwordIds, destinationVaultId, vaultPassword);
  }

  /**
   * Obtener estadísticas de vaults
   */
  async getVaultStats(): Promise<{ success: boolean; stats?: VaultStats; error?: string }> {
    try {
      const data = await this.makeRequest('/api/vault-stats/');
      return {
        success: data.success,
        stats: data.stats,
        error: data.error
      };
    } catch (error) {
      console.error('Error fetching vault stats:', error);
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Error al cargar estadísticas de vaults'
      };
    }
  }

  /**
   * Cambiar contraseña de un vault privado
   */
  async changeVaultPassword(
    vaultId: number,
    currentPassword: string,
    newPassword: string,
    _masterPassword?: string
  ): Promise<ApiResponse> {
    try {
      // 1) Material actual.
      const params = await this.makeRequest(`/api/vaults/${vaultId}/crypto-params/`);
      if (!params.success) {
        return { success: false, error: params.error || 'No se pudo obtener el material de la bóveda' };
      }

      // 2) Verificar la contraseña actual en local (y obtener su SubAuthKey como prueba).
      let currentSubAuthKey: string;
      try {
        ({ subAuthKey: currentSubAuthKey } = await unlockVaultSubKey(
          currentPassword,
          params.sub_kdf_salt,
          params.wrapped_vault_subkey,
          params.sub_kdf_params,
        ));
      } catch {
        return { success: false, error: 'Contraseña actual del vault incorrecta' };
      }

      // 3) Re-envolver la MISMA VaultSubKey con la contraseña nueva (no re-cifra entradas).
      const newSetup = await rotateVaultPassword(
        currentPassword,
        params.sub_kdf_salt,
        params.wrapped_vault_subkey,
        newPassword,
        params.sub_kdf_params,
      );

      const data = await this.makeRequest(`/api/vaults/${vaultId}/change-password/`, {
        method: 'POST',
        body: JSON.stringify({
          current_sub_auth_key: currentSubAuthKey,
          sub_kdf_salt: newSetup.subKdfSalt,
          sub_kdf_params: newSetup.subKdfParams,
          sub_auth_key: newSetup.subAuthKey,
          wrapped_vault_subkey: newSetup.wrappedVaultSubkey,
        })
      });

      // El cambio invalida el marcador en servidor; re-desbloquear con la prueba nueva y refrescar
      // la VaultSubKey en memoria (es la misma clave, re-derivada del material nuevo).
      if (data.success) {
        const { subKey } = await unlockVaultSubKey(
          newPassword,
          newSetup.subKdfSalt,
          newSetup.wrappedVaultSubkey,
          newSetup.subKdfParams,
        );
        await this.makeRequest(`/api/vaults/${vaultId}/unlock/`, {
          method: 'POST',
          body: JSON.stringify({ sub_auth_key: newSetup.subAuthKey })
        }).catch(() => {});
        cryptoSession.unlockVaultKey(vaultId, subKey);
      }

      return {
        success: data.success,
        message: data.message,
        error: data.error
      };
    } catch (error) {
      console.error('Error changing vault password:', error);
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Error al cambiar la contraseña del vault'
      };
    }
  }

  /**
   * Convertir vault entre público y privado
   */
  /**
   * Convertir una bóveda entre pública y privada (paso 24b). Cambia el dominio de clave de todas
   * las entradas, así que se re-cifran en el cliente: público→privado con `vaultPassword` como
   * contraseña NUEVA; privado→público con `vaultPassword` como contraseña ACTUAL. El servidor sólo
   * ve blobs opacos + material de subclave.
   */
  async convertVaultPrivacy(
    vaultId: number,
    makePrivate: boolean,
    vaultPassword: string
  ): Promise<ApiResponse> {
    try {
      if (!vaultPassword) {
        return { success: false, error: 'La contraseña de la bóveda es requerida' };
      }

      if (makePrivate) {
        // público → privado
        // 1) Entradas actuales (cifradas bajo la VaultKey principal).
        const listing = await this.makeRequest(`/api/vaults/${vaultId}/passwords/`);
        if (!listing.success) {
          return { success: false, error: listing.error || 'No se pudieron leer las contraseñas de la bóveda' };
        }
        const entries: any[] = listing.passwords || [];

        // 2) Descifrar todas bajo la clave principal ANTES de registrar la subclave.
        const decrypted: { id: number; clientId: string; payload: any }[] = [];
        for (const e of entries) {
          const payload = await cryptoSession.decryptEntryForVault(e.client_id, e.ciphertext, e.crypto_version, null);
          decrypted.push({ id: e.id, clientId: e.client_id, payload });
        }

        // 3) Generar la subclave y registrarla; re-cifrar cada entrada bajo ella.
        const { setup, subKey } = await setupVaultSubKey(vaultPassword);
        cryptoSession.unlockVaultKey(vaultId, subKey);
        const ciphertexts: Record<string, string> = {};
        try {
          for (const { id, clientId, payload } of decrypted) {
            ciphertexts[String(id)] = await cryptoSession.encryptEntryForVault(clientId, payload, vaultId);
          }

          const data = await this.makeRequest(`/api/vaults/${vaultId}/convert-privacy/`, {
            method: 'POST',
            body: JSON.stringify({
              make_private: true,
              sub_kdf_salt: setup.subKdfSalt,
              sub_kdf_params: setup.subKdfParams,
              sub_auth_key: setup.subAuthKey,
              wrapped_vault_subkey: setup.wrappedVaultSubkey,
              ciphertexts,
            }),
          });
          if (!data.success) cryptoSession.lockVaultKey(vaultId); // rollback del registro local
          return { success: data.success, message: data.message, error: data.error };
        } catch (err) {
          cryptoSession.lockVaultKey(vaultId);
          throw err;
        }
      } else {
        // privado → público
        // 1) Material de la bóveda y verificación de la contraseña actual en local.
        const params = await this.makeRequest(`/api/vaults/${vaultId}/crypto-params/`);
        if (!params.success) {
          return { success: false, error: params.error || 'No se pudo obtener el material de la bóveda' };
        }
        let subKey: CryptoKey;
        let subAuthKey: string;
        try {
          ({ subKey, subAuthKey } = await unlockVaultSubKey(
            vaultPassword, params.sub_kdf_salt, params.wrapped_vault_subkey, params.sub_kdf_params,
          ));
        } catch {
          return { success: false, error: 'Contraseña del vault incorrecta' };
        }

        // 2) Fijar el marcador de desbloqueo (para poder leer las entradas) y registrar la subclave.
        await this.makeRequest(`/api/vaults/${vaultId}/unlock/`, {
          method: 'POST',
          body: JSON.stringify({ sub_auth_key: subAuthKey }),
        }).catch(() => {});
        cryptoSession.unlockVaultKey(vaultId, subKey);

        // 3) Descifrar bajo la subclave y re-cifrar bajo la VaultKey principal.
        const listing = await this.makeRequest(`/api/vaults/${vaultId}/passwords/`);
        if (!listing.success) {
          return { success: false, error: listing.error || 'No se pudieron leer las contraseñas de la bóveda' };
        }
        const entries: any[] = listing.passwords || [];
        const ciphertexts: Record<string, string> = {};
        for (const e of entries) {
          const payload = await cryptoSession.decryptEntryForVault(e.client_id, e.ciphertext, e.crypto_version, vaultId);
          ciphertexts[String(e.id)] = await cryptoSession.encryptEntryForVault(e.client_id, payload, null);
        }

        const data = await this.makeRequest(`/api/vaults/${vaultId}/convert-privacy/`, {
          method: 'POST',
          body: JSON.stringify({
            make_private: false,
            current_sub_auth_key: subAuthKey,
            ciphertexts,
          }),
        });
        if (data.success) cryptoSession.lockVaultKey(vaultId); // ya es pública: clave principal
        return { success: data.success, message: data.message, error: data.error };
      }
    } catch (error) {
      console.error('Error converting vault privacy:', error);
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Error al cambiar la privacidad del vault'
      };
    }
  }

  /**
   * Buscar en vaults y contraseñas
   */
  async searchVaults(query: string, vaultId?: number | string): Promise<{
    success: boolean;
    results?: {
      vaults: Vault[];
      passwords: any[];
      query: string;
    };
    total_results?: number;
    error?: string;
  }> {
    try {
      const params = new URLSearchParams({ q: query });
      if (vaultId !== undefined) {
        params.append('vault_id', vaultId.toString());
      }

      const data = await this.makeRequest(`/api/vault-search/?${params}`);
      return {
        success: data.success,
        results: data.results,
        total_results: data.total_results,
        error: data.error
      };
    } catch (error) {
      console.error('Error searching vaults:', error);
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Error en la búsqueda'
      };
    }
  }
}

export const vaultService = new VaultService();