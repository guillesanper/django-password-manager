// services/settingsService.ts - Servicio para configuraciones de usuario
const API_BASE_URL = 'http://localhost:8000';

export interface UserSettings {
  theme: 'light' | 'dark' | 'pink';
  require_password_modify: boolean;
  require_password_delete: boolean;
  notifications: 'enabled' | 'disabled';
}

export interface SettingsResponse {
  success: boolean;
  settings?: UserSettings;
  error?: string;
  message?: string;
}

class SettingsService {
  private async getCSRFToken(): Promise<string> {
    const cookies = document.cookie.split(';');
    for (let cookie of cookies) {
      const [name, value] = cookie.trim().split('=');
      if (name === 'csrftoken') {
        return value;
      }
    }
    
    const csrfMeta = document.querySelector('meta[name="csrf-token"]') as HTMLMetaElement;
    if (csrfMeta) {
      return csrfMeta.content;
    }

    try {
      await fetch(`${API_BASE_URL}/`, {
        method: 'GET',
        credentials: 'include',
      });
      
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
      console.error('Settings Service Error:', error);
      throw error;
    }
  }

  /**
   * Obtener configuraciones del usuario
   */
  async getUserSettings(): Promise<SettingsResponse> {
    try {
      const data = await this.makeRequest('/api/settings/');
      
      return {
        success: data.success,
        settings: data.settings,
        error: data.error
      };
    } catch (error) {
      console.error('Error fetching user settings:', error);
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Error al cargar configuraciones'
      };
    }
  }

  /**
   * Actualizar configuraciones del usuario
   */
  async updateUserSettings(settings: Partial<UserSettings>): Promise<SettingsResponse> {
    try {
      const data = await this.makeRequest('/api/settings/update/', {
        method: 'POST',
        body: JSON.stringify(settings)
      });

      return {
        success: data.success,
        message: data.message || 'Configuraciones actualizadas exitosamente',
        error: data.error
      };
    } catch (error) {
      console.error('Error updating user settings:', error);
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Error al actualizar configuraciones'
      };
    }
  }

  /**
   * Cambiar tema de la aplicación
   */
  async updateTheme(theme: UserSettings['theme']): Promise<SettingsResponse> {
    return this.updateUserSettings({ theme });
  }

  /**
   * Actualizar configuraciones de seguridad
   */
  async updateSecuritySettings(settings: {
    require_password_modify?: boolean;
    require_password_delete?: boolean;
  }): Promise<SettingsResponse> {
    return this.updateUserSettings(settings);
  }

  /**
   * Actualizar configuraciones de notificaciones
   */
  async updateNotifications(notifications: UserSettings['notifications']): Promise<SettingsResponse> {
    return this.updateUserSettings({ notifications });
  }
}

export const settingsService = new SettingsService();