// services/vaultService.ts - Servicio para manejar operaciones de vaults
import { authService } from './authService'

const API_BASE_URL = 'http://localhost:8000';

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
        throw new Error(errorData.error || `Error ${response.status}: ${response.statusText}`);
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
      const data = await this.makeRequest('/api/vaults/create/', {
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
   * Eliminar un vault
   */
  async deleteVault(
    vaultId: number, 
    masterPassword: string,
    movePasswordsToVault?: number
  ): Promise<ApiResponse> {
    try {
      const data = await this.makeRequest(`/api/vaults/${vaultId}/delete/`, {
        method: 'POST',
        body: JSON.stringify({
          master_password: masterPassword,
          move_passwords_to_vault: movePasswordsToVault
        })
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
      const data = await this.makeRequest(`/api/vaults/${vaultId}/unlock/`, {
        method: 'POST',
        body: JSON.stringify({
          vault_password: vaultPassword
        })
      });

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
        error: error instanceof Error ? error.message : 'Error al cargar las contraseñas del vault'
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
   * Mover una contraseña a un vault diferente
   */
  async movePasswordToVault(
    passwordId: number, 
    vaultId: number | null,
    vaultPassword?: string
  ): Promise<ApiResponse> {
    try {
      const data = await this.makeRequest('/api/passwords/move/', {
        method: 'POST',
        body: JSON.stringify({
          password_id: passwordId,
          vault_id: vaultId,
          vault_password: vaultPassword
        })
      });

      return {
        success: data.success,
        message: data.message,
        error: data.error
      };
    } catch (error) {
      console.error('Error moving password:', error);
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Error al mover la contraseña'
      };
    }
  }

  /**
   * Mover múltiples contraseñas a un vault
   */
  async batchMovePasswords(
    passwordIds: number[], 
    destinationVaultId: number | null,
    vaultPassword?: string
  ): Promise<ApiResponse> {
    try {
      const data = await this.makeRequest('/api/vaults/batch-move-passwords/', {
        method: 'POST',
        body: JSON.stringify({
          password_ids: passwordIds,
          destination_vault_id: destinationVaultId,
          vault_password: vaultPassword
        })
      });

      return {
        success: data.success,
        message: data.message,
        error: data.error
      };
    } catch (error) {
      console.error('Error batch moving passwords:', error);
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Error al mover las contraseñas'
      };
    }
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
    masterPassword: string
  ): Promise<ApiResponse> {
    try {
      const data = await this.makeRequest(`/api/vaults/${vaultId}/change-password/`, {
        method: 'POST',
        body: JSON.stringify({
          current_vault_password: currentPassword,
          new_vault_password: newPassword,
          master_password: masterPassword
        })
      });

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
  async convertVaultPrivacy(
    vaultId: number,
    makePrivate: boolean,
    masterPassword: string,
    vaultPassword?: string
  ): Promise<ApiResponse> {
    try {
      const data = await this.makeRequest(`/api/vaults/${vaultId}/convert-privacy/`, {
        method: 'POST',
        body: JSON.stringify({
          make_private: makePrivate,
          vault_password: vaultPassword,
          master_password: masterPassword
        })
      });

      return {
        success: data.success,
        message: data.message,
        error: data.error
      };
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