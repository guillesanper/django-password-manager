// services/masterKeyService.ts - URLs corregidas y CSRF mejorado
import { authService } from './authService';

const API_BASE_URL = 'http://localhost:8000';

export interface MasterKeyResponse {
  success: boolean;
  error?: string;
  message?: string;
}

class MasterKeyService {
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
      console.error('Masterkey Service Error:', error);
      throw error;
    }
  }

  /**
   * Configura la clave maestra del usuario
   */
  async setMasterKey(masterKey: string): Promise<MasterKeyResponse> {
    console.log('🔐 Configurando clave maestra...');
    return this.makeRequest('/api/master-key/setup/', { // URL corregida
      method: 'POST',
      body: JSON.stringify({
        master_key: masterKey
      })
    });
  }

  /**
   * Verifica si el usuario ya tiene una clave maestra configurada
   */
  async hasMasterKey(): Promise<{ success: boolean; hasMasterKey: boolean; error?: string }> {
    try {
      console.log('🔐 Verificando si tiene clave maestra...');
      const response = await this.makeRequest('/api/master-key/check/', { // URL corregida
        method: 'GET'
      });

      if (response.success) {
        return {
          success: true,
          hasMasterKey: (response as any).hasMasterKey || false
        };
      }

      return {
        success: false,
        hasMasterKey: false,
        error: response.error
      };
    } catch (error) {
      return {
        success: false,
        hasMasterKey: false,
        error: 'Error al verificar la clave maestra'
      };
    }
  }

  /**
   * Verifica una clave maestra
   */
  async verifyMasterKey(masterKey: string): Promise<MasterKeyResponse> {
    console.log('🔐 Verificando clave maestra...');
    return this.makeRequest('/api/master-key/verify/', { // URL corregida
      method: 'POST',
      body: JSON.stringify({
        master_key: masterKey
      })
    });
  }

  /**
   * Cambia la clave maestra (requiere la clave actual)
   */
  async changeMasterKey(currentKey: string, newKey: string): Promise<MasterKeyResponse> {
    console.log('🔐 Cambiando clave maestra...');
    return this.makeRequest('/api/master-key/change/', { // URL corregida
      method: 'POST',
      body: JSON.stringify({
        current_master_key: currentKey,
        new_master_key: newKey
      })
    });
  }
}

export const masterKeyService = new MasterKeyService();