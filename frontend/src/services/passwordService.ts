// services/passwordService.ts
import { type PasswordAccount } from '../components/account/AccountCard';
import { type AddPasswordData } from '../components/account/AddPasswordModal';

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

class PasswordService {
  private async getCSRFToken(): Promise<string> {
    // Obtener token CSRF desde las cookies
    const cookies = document.cookie.split(';');
    for (let cookie of cookies) {
      const [name, value] = cookie.trim().split('=');
      if (name === 'csrftoken') {
        return value;
      }
    }
    
    // Si no está en cookies, intentar obtenerlo del meta tag
    const csrfMeta = document.querySelector('meta[name="csrf-token"]') as HTMLMetaElement;
    if (csrfMeta) {
      return csrfMeta.content;
    }

    // Si no existe, hacer una petición GET para obtenerlo
    try {
      await fetch(`${API_BASE_URL}/`, {
        method: 'GET',
        credentials: 'include',
      });
      
      // Intentar obtenerlo nuevamente después de la petición
      const newCookies = document.cookie.split(';');
      for (let cookie of newCookies) {
        const [name, value] = cookie.trim().split('=');
        if (name === 'csrftoken') {
          return value;
        }
      }
    } catch (error) {
      console.warn('No se pudo obtener el token CSRF:', error);
    }
    
    return '';
  }

  private async makeRequest(
    endpoint: string,
    options: RequestInit = {}
  ): Promise<any> {
    try {
      const csrfToken = await this.getCSRFToken();
      
      const response = await fetch(`${API_BASE_URL}${endpoint}`, {
        headers: {
          'Content-Type': 'application/json',
          'X-CSRFToken': csrfToken,
          'Accept': 'application/json',
          ...options.headers,
        },
        credentials: 'include',
        ...options,
      });

      if (!response.ok) {
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
   * Obtener todas las cuentas del usuario
   */
  async getAccounts(): Promise<PasswordAccount[]> {
    try {
      const data = await this.makeRequest('/api/accounts/');
      return data.accounts || [];
    } catch (error) {
      console.error('Error fetching accounts:', error);
      throw new Error('Error al cargar las contraseñas');
    }
  }

  /**
   * Crear una nueva cuenta de contraseña
   */
  async createAccount(accountData: AddPasswordData): Promise<ApiResponse> {
    try {
      // Usar FormData para enviar datos como el backend espera
      const formData = new FormData();
      formData.append('website', accountData.website);
      formData.append('username', accountData.username);
      formData.append('password', accountData.password);
      formData.append('algorithm', accountData.algorithm);

      const csrfToken = await this.getCSRFToken();
      
      const response = await fetch(`${API_BASE_URL}/passwords/add/`, {
        method: 'POST',
        headers: {
          'X-CSRFToken': csrfToken,
          'Accept': 'application/json',
        },
        credentials: 'include',
        body: formData
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        return {
          success: false,
          error: errorData.error || 'Error al crear la contraseña'
        };
      }

      const data = await response.json();
      return {
        success: true,
        message: data.message || 'Contraseña creada exitosamente'
      };
    } catch (error) {
      console.error('Error creating account:', error);
      return {
        success: false,
        error: 'Error de conexión al crear la contraseña'
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
    accountData: Partial<AddPasswordData>,
    masterPassword?: string
  ): Promise<ApiResponse> {
    try {
      // Usar FormData para mantener consistencia con el backend
      const formData = new FormData();
      
      if (accountData.website) formData.append('website', accountData.website);
      if (accountData.username) formData.append('username', accountData.username);
      if (accountData.password) formData.append('password', accountData.password);
      if (accountData.algorithm) formData.append('algorithm', accountData.algorithm);
      if (masterPassword) formData.append('master_password', masterPassword);

      const csrfToken = await this.getCSRFToken();
      
      const response = await fetch(`${API_BASE_URL}/passwords/${passwordId}/update/`, {
        method: 'POST',
        headers: {
          'X-CSRFToken': csrfToken,
          'Accept': 'application/json',
        },
        credentials: 'include',
        body: formData
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        return {
          success: false,
          error: errorData.error || 'Error al actualizar la contraseña'
        };
      }

      const data = await response.json();
      return {
        success: true,
        message: data.message || 'Contraseña actualizada exitosamente'
      };
    } catch (error) {
      console.error('Error updating password:', error);
      return {
        success: false,
        error: 'Error de conexión al actualizar la contraseña'
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