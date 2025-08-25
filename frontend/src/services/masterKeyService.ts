// services/masterKeyService.ts - URLs corregidas y CSRF mejorado

const API_BASE_URL = 'http://localhost:8000';

export interface MasterKeyResponse {
  success: boolean;
  error?: string;
  message?: string;
}

class MasterKeyService {
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
  ): Promise<MasterKeyResponse> {
    try {
      // Obtener el token CSRF
      const csrfToken = await this.getCSRFToken();
      console.log('🔐 Token CSRF obtenido:', csrfToken ? 'Sí' : 'No');
      
      const response = await fetch(`${API_BASE_URL}${endpoint}`, {
        headers: {
          'Content-Type': 'application/json',
          'X-CSRFToken': csrfToken,
          'Accept': 'application/json',
          ...options.headers,
        },
        credentials: 'include', // Cambio crítico: usar 'include' en lugar de 'same-origin'
        ...options,
      });

      console.log('🔐 Response status:', response.status);

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        console.error('🔐 Error response:', errorData);
        return {
          success: false,
          error: errorData.error || `Error ${response.status}: ${response.statusText}`
        };
      }

      const data = await response.json();
      console.log('🔐 Success response:', data);
      return data;
    } catch (error) {
      console.error('Master Key Service Error:', error);
      return {
        success: false,
        error: 'Error de conexión. Verifica tu conexión a internet.'
      };
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