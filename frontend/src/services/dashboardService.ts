// services/dashboardService.ts - CORREGIDO con autenticación JWT
import { authService } from './authService';

import { API_BASE_URL } from '../config/api';

export interface DashboardStats {
  passwords_count: number;
  files_count: number;
  active_sessions: number;
  security_score: number;
  vault_summary?: {
    total_vaults: number;
    private_vaults: number;
    public_vaults: number;
    unvaulted_passwords: number;
    vaulted_passwords: number;
    vault_list: Array<{
      id: number;
      name: string;
      color: string;
      is_private: boolean;
      password_count: number;
    }>;
  };
}

export interface ActivityItem {
  type: string;
  title: string;
  description: string;
  time: string;
  activity_type: 'success' | 'info' | 'warning' | 'error';
}

export interface SecuritySummary {
  strong_passwords: number;
  needs_update: number;
  old_passwords: number;
  total_passwords: number;
}

export interface DashboardStatsResponse {
  success: boolean;
  stats?: DashboardStats;
  error?: string;
}

export interface RecentActivityResponse {
  success: boolean;
  activities?: ActivityItem[];
  error?: string;
}

export interface SecuritySummaryResponse {
  success: boolean;
  summary?: SecuritySummary;
  error?: string;
}

class DashboardService {
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
   * Obtener estadísticas del dashboard
   */
  async getDashboardStats(): Promise<DashboardStatsResponse> {
    try {
      const data = await this.makeRequest('/api/dashboard/stats/');
      return { 
        success: true, 
        stats: {
          passwords_count: data.passwords_count,
          files_count: data.files_count,
          active_sessions: data.active_sessions,
          security_score: data.security_score,
          vault_summary: data.vault_summary
        }
      };
    } catch (error) {
      console.error('Error fetching dashboard stats:', error);
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Error al cargar estadísticas'
      };
    }
  }

  /**
   * Obtener actividad reciente
   */
  async getRecentActivity(): Promise<RecentActivityResponse> {
    try {
      const data = await this.makeRequest('/api/dashboard/recent-activity/');
      return { 
        success: true, 
        activities: data.activities || []
      };
    } catch (error) {
      console.error('Error fetching recent activity:', error);
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Error al cargar actividad reciente'
      };
    }
  }

  /**
   * Obtener resumen de seguridad
   */
  async getSecuritySummary(): Promise<SecuritySummaryResponse> {
    try {
      const data = await this.makeRequest('/api/dashboard/security-summary/');
      return { 
        success: true, 
        summary: {
          strong_passwords: data.strong_passwords,
          needs_update: data.needs_update,
          old_passwords: data.old_passwords,
          total_passwords: data.total_passwords
        }
      };
    } catch (error) {
      console.error('Error fetching security summary:', error);
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Error al cargar resumen de seguridad'
      };
    }
  }
}

export const dashboardService = new DashboardService();