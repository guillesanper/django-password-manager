// services/dashboardService.ts
const API_BASE_URL = 'http://localhost:8000';

export interface DashboardStats {
  passwords_count: number;
  files_count: number;
  active_sessions: number;
  security_score: number;
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

  private async makeRequest(endpoint: string, options: RequestInit = {}): Promise<any> {
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
          security_score: data.security_score
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