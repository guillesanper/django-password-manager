// services/passwordService.ts - Corregido para manejar vaults apropiadamente
import { type PasswordAccount } from '../components/account/AccountCard';
import { type AddPasswordData } from '../components/account/AddPasswordModal';
import { authService } from './authService';

const API_BASE_URL = 'http://localhost:8000';

export interface UnlockPasswordRequest {
  master_password: string;
}

export interface UnlockPasswordResponse {
  success: boolean;
  password?: string;
  account?: {
    id: number;
    website: string;
    username: string;
  };
  error?: string;
}

export interface DeletePasswordRequest {
  master_password: string;
}

export interface ApiResponse {
  success: boolean;
  error?: string;
  message?: string;
}

// Nueva interfaz para crear contraseña con vault
export interface AddPasswordWithVaultData extends AddPasswordData {
  vault_id?: number | null;
  vault_password?: string;
  vault_already_unlocked?: boolean;  

}

class PasswordService {
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
      console.error('Password Service Error:', error);
      throw error;
    }
  }
  /**
   * Obtener todas las cuentas del usuario (con soporte para filtrado por vault)
   */
  async getAccounts(vaultId?: number | string | null): Promise<PasswordAccount[]> {
    try {
      let endpoint = '/api/accounts/';
      
      // Agregar parámetro de vault si se especifica
      if (vaultId !== undefined) {
        const params = new URLSearchParams();
        if (vaultId === null || vaultId === 'unvaulted') {
          params.append('vault_id', 'unvaulted');
        } else {
          params.append('vault_id', vaultId.toString());
        }
        endpoint += `?${params}`;
      }

      const data = await this.makeRequest(endpoint);
      return data.accounts || [];
    } catch (error) {
      console.error('Error fetching accounts:', error);
      throw new Error('Error al cargar las contraseñas');
    }
  }

  /**
   * 🔧 FIX: Usar el mismo endpoint que getAccounts ya que /api/accounts-with-vaults/ no existe
   */
  async getAccountsWithVaults(vaultId?: number | string | null): Promise<PasswordAccount[]> {
    console.log('🔍 getAccountsWithVaults called with vaultId:', vaultId);
    return this.getAccounts(vaultId);
  }

  /**
   * Crear una nueva cuenta de contraseña - ACTUALIZADO para soportar vaults
   */
  async createAccount(accountData: AddPasswordWithVaultData): Promise<ApiResponse> {
    try {
      console.log('🚀 Creating account with data:', {
        website: accountData.website,
        username: accountData.username,
        algorithm: accountData.algorithm,
        vault_id: accountData.vault_id,
        has_vault_password: !!accountData.vault_password,
        vault_already_unlocked: accountData.vault_already_unlocked

      });

      const requestBody = {
        website: accountData.website,
        username: accountData.username,
        password: accountData.password,
        algorithm: accountData.algorithm,
        vault_id: accountData.vault_id || null,
        vault_password: accountData.vault_password || '',
        vault_already_unlocked: accountData.vault_already_unlocked || false  // NUEVO campo

      };

      const data = await this.makeRequest('/passwords/add/', {
        method: 'POST',
        body: JSON.stringify(requestBody)
      });

      return {
        success: data.success,
        message: data.message || 'Contraseña creada exitosamente'
      };
    } catch (error) {
      console.error('❌ Error creating account:', error);
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Error de conexión al crear la contraseña'
      };
    }
  }

  /**
   * Desbloquear una contraseña específica
   */
  async unlockPassword(
    passwordId: number, 
    masterPassword: string
  ): Promise<UnlockPasswordResponse> {
    try {
      const data = await this.makeRequest(`/api/unlock-password/${passwordId}/`, {
        method: 'POST',
        body: JSON.stringify({
          master_password: masterPassword
        })
      });

      return {
        success: data.success,
        password: data.password,
        account: data.account,
        error: data.error
      };
    } catch (error) {
      console.error('Error unlocking password:', error);
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Error al desbloquear la contraseña'
      };
    }
  }

  /**
   * Eliminar una contraseña
   */
  async deletePassword(
    passwordId: number, 
    masterPassword: string
  ): Promise<ApiResponse> {
    try {
      const data = await this.makeRequest(`/passwords/${passwordId}/delete/`, {
        method: 'POST',
        body: JSON.stringify({
          master_password: masterPassword
        })
      });

      return {
        success: data.success,
        message: data.message,
        error: data.error
      };
    } catch (error) {
      console.error('Error deleting password:', error);
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Error al eliminar la contraseña'
      };
    }
  }

  /**
   * Actualizar una contraseña
   */
  async updatePassword(
    passwordId: number, 
    accountData: Partial<AddPasswordWithVaultData>,
    masterPassword?: string
  ): Promise<ApiResponse> {
    try {
      const updateData: any = {};
      
      if (accountData.website) updateData.website = accountData.website;
      if (accountData.username) updateData.username = accountData.username;
      if (accountData.algorithm) updateData.algorithm = accountData.algorithm;
      
      // Solo incluir contraseña y master_password si se está cambiando la contraseña
      if (accountData.password) {
        updateData.password = accountData.password;
        if (masterPassword) {
          updateData.master_password = masterPassword;
        }
      }

      const data = await this.makeRequest(`/passwords/${passwordId}/update/`, {
        method: 'POST',
        body: JSON.stringify(updateData)
      });

      return {
        success: data.success,
        message: data.message || 'Contraseña actualizada exitosamente'
      };
    } catch (error) {
      console.error('Error updating password:', error);
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Error de conexión al actualizar la contraseña'
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
      const data = await this.makeRequest('/api/batch-move-passwords/', {
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
   * Desbloquear todas las contraseñas
   */
  async unlockAllPasswords(masterPassword: string): Promise<{
    success: boolean;
    accounts?: PasswordAccount[];
    error?: string;
  }> {
    try {
      const data = await this.makeRequest('/api/unlock-all-accounts/', {
        method: 'POST',
        body: JSON.stringify({
          master_password: masterPassword
        })
      });

      return {
        success: data.success,
        accounts: data.accounts,
        error: data.error
      };
    } catch (error) {
      console.error('Error unlocking all passwords:', error);
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Error al desbloquear las contraseñas'
      };
    }
  }

  /**
   * Eliminar múltiples contraseñas en lote
   */
  async batchDeletePasswords(
    passwordIds: number[], 
    masterPassword: string
  ): Promise<ApiResponse> {
    try {
      const data = await this.makeRequest('/api/batch-delete-passwords/', {
        method: 'POST',
        body: JSON.stringify({
          password_ids: passwordIds,
          master_password: masterPassword
        })
      });

      return {
        success: data.success,
        message: data.message,
        error: data.error
      };
    } catch (error) {
      console.error('Error batch deleting passwords:', error);
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Error al eliminar las contraseñas'
      };
    }
  }

  /**
   * Generar contraseñas
   */
  async generatePasswords(
    count: number = 5,
    length: number = 20,
    useSpecial: boolean = true,
    useNumbers: boolean = true
  ): Promise<{
    success: boolean;
    passwords?: string[];
    error?: string;
  }> {
    try {
      const params = new URLSearchParams({
        count: count.toString(),
        length: length.toString(),
        special: useSpecial.toString(),
        numbers: useNumbers.toString()
      });

      const data = await this.makeRequest(`/api/password-generator/?${params}`);

      return {
        success: true,
        passwords: data.passwords
      };
    } catch (error) {
      console.error('Error generating passwords:', error);
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Error al generar contraseñas'
      };
    }
  }
}

export const passwordService = new PasswordService();