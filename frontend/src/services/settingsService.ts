// services/settingsService.ts - Servicio para configuraciones de usuario
import { authService } from './authService'

import { API_BASE_URL } from '../config/api';

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