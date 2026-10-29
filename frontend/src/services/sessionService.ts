// src/services/sessionService.ts
import { authService } from './authService';

export interface DeviceInfo {
  browser: string;
  os: string;
  device: string;
  is_mobile: boolean;
  is_tablet: boolean;
  is_pc: boolean;
  user_agent: string;
}

export interface LocationInfo {
  country: string;
  city: string;
  region: string;
  lat?: number;
  lon?: number;
}

export interface SecurityAlert {
  type: 'geographic_anomaly' | 'new_device' | 'multiple_sessions' | 'rapid_login' | 'unusual_time';
  message: string;
  severity: 'low' | 'medium' | 'high';
  risk_score: number;
}

export interface SecurityAnalysis {
  is_suspicious: boolean;
  alerts: SecurityAlert[];
  risk_factors: string[];
  risk_score: number;
  security_score: number;
  recommendation: 'low_risk' | 'medium_risk' | 'high_risk';
}

export interface Session {
  session_id: string;
  user_id: number;
  username: string;
  email: string;
  created_at: string;
  last_activity: string;
  expires_at: string;
  ip_address: string;
  device_fingerprint: string;
  device_info: DeviceInfo;
  location: LocationInfo;
  is_active: boolean;
  login_method: string;
  security_score: number;
  activities_count: number;
  flags: string[];
  security_analysis?: SecurityAnalysis;
  is_current?: boolean;
  duration_minutes?: number;
  inactive_minutes?: number;
  has_security_flags?: boolean;
  security_level?: 'compromised' | 'low' | 'medium' | 'high';
  recent_activities?: Array<{
    type: string;
    timestamp: string;
  }>;
}

export interface SessionStatistics {
  total_sessions: number;
  active_sessions: number;
  unique_devices: number;
  unique_locations: number;
  last_login: string | null;
  security_summary: {
    status: 'no_sessions' | 'good' | 'warning' | 'critical';
    issues?: number;
    compromised_sessions?: number;
    high_risk_sessions?: number;
  };
  sessions: Session[];
  total_activities?: number;
  average_session_duration?: number;
}

export interface SecurityReport {
  user_id: number;
  generated_at: string;
  summary: SessionStatistics['security_summary'];
  metrics: {
    total_sessions: number;
    unique_locations: number;
    unique_devices: number;
  };
  security_analysis: {
    high_risk_sessions: number;
    compromised_sessions: number;
    unusual_locations: Array<{
      session_id: string;
      location: LocationInfo;
      created_at: string;
    }>;
    unusual_devices: any[];
    time_patterns: Record<string, any>;
  };
  recommendations: Array<{
    type: string;
    priority: 'low' | 'medium' | 'high';
    message: string;
  }>;
}

export interface SessionServiceResponse<T> {
  success: boolean;
  data?: T;
  error?: string;
  message?: string;
}

import { API_BASE_URL } from '../config/api';

class SessionService {
  private readonly baseURL = '/api/sessions';

  private async getAuthHeaders(): Promise<Record<string, string>> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
    };

    const token = authService.getAccessToken();
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }

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
          console.error('Autenticación requerida');
          window.dispatchEvent(new CustomEvent('auth:sessionExpired'));
          throw new Error('Sesión expirada. Por favor, inicia sesión nuevamente.');
        }

        const errorData = await response.json().catch(() => ({}));
        throw new Error(errorData.error || `Error ${response.status}: ${response.statusText}`);
      }

      return await response.json();
    } catch (error) {
      console.error('Session Service Error:', error);
      throw error;
    }
  }

  async getUserSessions(): Promise<SessionServiceResponse<SessionStatistics>> {
    try {
      const data = await this.makeRequest(`${this.baseURL}/list/`);
      return {
        success: true,
        data: data.sessions
      };
    } catch (error: any) {
      console.error('Error fetching user sessions:', error);
      return {
        success: false,
        error: error.message || 'Error al obtener sesiones'
      };
    }
  }

  async terminateSession(sessionId: string, reason: string = 'user_request'): Promise<SessionServiceResponse<void>> {
    try {
      const data = await this.makeRequest(`${this.baseURL}/terminate/`, {
        method: 'POST',
        body: JSON.stringify({
          session_id: sessionId,
          reason
        })
      });
      return {
        success: true,
        message: data.message
      };
    } catch (error: any) {
      console.error('Error terminating session:', error);
      return {
        success: false,
        error: error.message || 'Error al terminar sesión'
      };
    }
  }

  async terminateAllOtherSessions(reason: string = 'user_request_all'): Promise<SessionServiceResponse<{ terminated_count: number }>> {
    try {
      const data = await this.makeRequest(`${this.baseURL}/terminate-all/`, {
        method: 'POST',
        body: JSON.stringify({
          confirm: true,
          reason
        })
      });
      return {
        success: true,
        data: { terminated_count: data.terminated_count },
        message: data.message
      };
    } catch (error: any) {
      console.error('Error terminating all sessions:', error);
      return {
        success: false,
        error: error.message || 'Error al terminar todas las sesiones'
      };
    }
  }

  async flagSessionSuspicious(sessionId: string, reason: string = 'user_report'): Promise<SessionServiceResponse<void>> {
    try {
      const data = await this.makeRequest(`${this.baseURL}/flag-suspicious/`, {
        method: 'POST',
        body: JSON.stringify({
          session_id: sessionId,
          reason
        })
      });
      return {
        success: true,
        message: data.message
      };
    } catch (error: any) {
      console.error('Error flagging session:', error);
      return {
        success: false,
        error: error.message || 'Error al marcar sesión como sospechosa'
      };
    }
  }

  async getSecurityReport(): Promise<SessionServiceResponse<SecurityReport>> {
    try {
      const data = await this.makeRequest(`${this.baseURL}/security-report/`);
      return {
        success: true,
        data: data.security_report
      };
    } catch (error: any) {
      console.error('Error fetching security report:', error);
      return {
        success: false,
        error: error.message || 'Error al obtener reporte de seguridad'
      };
    }
  }

  async getSessionActivities(sessionId: string): Promise<SessionServiceResponse<Array<{ type: string; timestamp: string }>>> {
    try {
      const data = await this.makeRequest(`${this.baseURL}/${sessionId}/activities/`);
      return {
        success: true,
        data: data.activities
      };
    } catch (error: any) {
      console.error('Error fetching session activities:', error);
      return {
        success: false,
        error: error.message || 'Error al obtener actividades'
      };
    }
  }

  // Utilidades para formateo
  formatTimeAgo(isoString: string): string {
    const date = new Date(isoString);
    const now = new Date();
    const diffMs = now.getTime() - date.getTime();
    const diffMins = Math.floor(diffMs / 60000);
    
    if (diffMins < 1) return 'Ahora mismo';
    if (diffMins < 60) return `Hace ${diffMins} min`;
    
    const diffHours = Math.floor(diffMins / 60);
    if (diffHours < 24) return `Hace ${diffHours}h`;
    
    const diffDays = Math.floor(diffHours / 24);
    if (diffDays < 30) return `Hace ${diffDays}d`;
    
    const diffMonths = Math.floor(diffDays / 30);
    return `Hace ${diffMonths} mes${diffMonths > 1 ? 'es' : ''}`;
  }

  getSeverityColor(severity: 'low' | 'medium' | 'high'): string {
    switch (severity) {
      case 'low': return '#10b981';
      case 'medium': return '#f59e0b';
      case 'high': return '#ef4444';
      default: return '#6b7280';
    }
  }

  

  getDeviceIcon(deviceInfo: DeviceInfo): string {
    if (deviceInfo.is_mobile) return '📱';
    if (deviceInfo.is_tablet) return '📱';
    if (deviceInfo.is_pc) return '💻';
    return '🖥️';
  }
}

export const sessionService = new SessionService();