// services/securityService.ts
import { authService } from './authService' 

import { API_BASE_URL } from '../config/api';

export interface PasswordStrength {
  level: 'very_weak' | 'weak' | 'moderate' | 'strong' | 'very_strong';
  label: string;
  color: string;
  score: number;
}

export interface BreachInfo {
  is_breached: boolean;
  breach_count: number;
  message: string;
  error?: boolean;
}

export interface PasswordAnalysis {
  id: number;
  website: string;
  username: string;
  entropy: number;
  strength: PasswordStrength;
  breach_info: BreachInfo;
  age_days: number;
  last_updated_days: number;
}

export interface SecurityIssue {
  type: 'weak_passwords' | 'breached_passwords' | 'duplicate_passwords' | 'old_passwords';
  count: number;
  severity: 'low' | 'medium' | 'high' | 'critical';
  message: string;
}

export interface SecurityPatterns {
  duplicate_groups: number;
  length_distribution: Record<number, number>;
  character_usage_stats: {
    uppercase: number;
    lowercase: number;
    digits: number;
    special: number;
  };
}

export interface SecurityAnalysis {
  overall_score: number;
  average_entropy: number;
  strength_distribution: Record<string, number>;
  security_issues: SecurityIssue[];
  recommendations: string[];
  patterns: SecurityPatterns;
}

export interface SecurityAnalysisResponse {
  success: boolean;
  total_passwords: number;
  analysis: SecurityAnalysis;
  passwords: PasswordAnalysis[];
  error?: string;
}

export interface SecurityRecommendation {
  type: string;
  priority: 'low' | 'medium' | 'high';
  title: string;
  description: string;
  action: string;
  count?: number;
}

export interface SecurityRecommendationsResponse {
  success: boolean;
  recommendations: SecurityRecommendation[];
  error?: string;
}

export interface CheckBreachRequest {
  password_id: number;
  master_password: string;
}

export interface CheckBreachResponse {
  success: boolean;
  password_id: number;
  breach_info: BreachInfo;
  error?: string;
}

class SecurityService {
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
   * Obtener análisis completo de seguridad
   */
  async getSecurityAnalysis(): Promise<SecurityAnalysisResponse> {
    try {
      const data = await this.makeRequest('/api/security/analysis/');
      return {
        success: true,
        total_passwords: data.total_passwords,
        analysis: data.analysis,
        passwords: data.passwords || []
      };
    } catch (error) {
      console.error('Error fetching security analysis:', error);
      return {
        success: false,
        total_passwords: 0,
        analysis: {
          overall_score: 0,
          average_entropy: 0,
          strength_distribution: {},
          security_issues: [],
          recommendations: [],
          patterns: {
            duplicate_groups: 0,
            length_distribution: {},
            character_usage_stats: {
              uppercase: 0,
              lowercase: 0,
              digits: 0,
              special: 0
            }
          }
        },
        passwords: [],
        error: error instanceof Error ? error.message : 'Error al cargar el análisis de seguridad'
      };
    }
  }

  /**
   * Verificar una contraseña específica contra HaveIBeenPwned
   */
  async checkPasswordBreach(passwordId: number, masterPassword: string): Promise<CheckBreachResponse> {
    try {
      const data = await this.makeRequest('/api/security/check-breach/', {
        method: 'POST',
        body: JSON.stringify({
          password_id: passwordId,
          master_password: masterPassword
        })
      });

      return {
        success: true,
        password_id: data.password_id,
        breach_info: data.breach_info
      };
    } catch (error) {
      console.error('Error checking password breach:', error);
      return {
        success: false,
        password_id: passwordId,
        breach_info: {
          is_breached: false,
          breach_count: 0,
          message: 'Error al verificar la contraseña',
          error: true
        },
        error: error instanceof Error ? error.message : 'Error al verificar la contraseña'
      };
    }
  }

  /**
   * Obtener recomendaciones de seguridad personalizadas
   */
  async getSecurityRecommendations(): Promise<SecurityRecommendationsResponse> {
    try {
      const data = await this.makeRequest('/api/security/recommendations/');
      return {
        success: true,
        recommendations: data.recommendations || []
      };
    } catch (error) {
      console.error('Error fetching security recommendations:', error);
      return {
        success: false,
        recommendations: [],
        error: error instanceof Error ? error.message : 'Error al cargar las recomendaciones'
      };
    }
  }

  /**
   * Utilidades para análisis local
   */
  getStrengthColor(strength: PasswordStrength): string {
    return strength.color;
  }

  getStrengthProgress(strength: PasswordStrength): number {
    return strength.score;
  }

  getSeverityColor(severity: SecurityIssue['severity']): string {
    switch (severity) {
      case 'critical': return '#dc2626';
      case 'high': return '#ea580c';
      case 'medium': return '#d97706';
      case 'low': return '#65a30d';
      default: return '#6b7280';
    }
  }

  getPriorityColor(priority: SecurityRecommendation['priority']): string {
    switch (priority) {
      case 'high': return '#dc2626';
      case 'medium': return '#d97706';
      case 'low': return '#059669';
      default: return '#6b7280';
    }
  }

  formatBreachCount(count: number): string {
    if (count >= 1000000) {
      return `${(count / 1000000).toFixed(1)}M`;
    } else if (count >= 1000) {
      return `${(count / 1000).toFixed(1)}K`;
    }
    return count.toString();
  }

  calculateOverallSecurityGrade(score: number): { grade: string; color: string; description: string } {
    if (score >= 90) {
      return {
        grade: 'A+',
        color: '#10b981',
        description: 'Excelente seguridad'
      };
    } else if (score >= 80) {
      return {
        grade: 'A',
        color: '#059669',
        description: 'Muy buena seguridad'
      };
    } else if (score >= 70) {
      return {
        grade: 'B',
        color: '#3b82f6',
        description: 'Buena seguridad'
      };
    } else if (score >= 60) {
      return {
        grade: 'C',
        color: '#f59e0b',
        description: 'Seguridad moderada'
      };
    } else if (score >= 50) {
      return {
        grade: 'D',
        color: '#f97316',
        description: 'Seguridad deficiente'
      };
    } else {
      return {
        grade: 'F',
        color: '#ef4444',
        description: 'Seguridad muy deficiente'
      };
    }
  }

  getAgeCategory(days: number): { category: string; color: string; urgent: boolean } {
    if (days > 730) { // > 2 años
      return {
        category: 'Muy antigua',
        color: '#dc2626',
        urgent: true
      };
    } else if (days > 365) { // > 1 año
      return {
        category: 'Antigua',
        color: '#ea580c',
        urgent: true
      };
    } else if (days > 180) { // > 6 meses
      return {
        category: 'Moderada',
        color: '#d97706',
        urgent: false
      };
    } else {
      return {
        category: 'Reciente',
        color: '#059669',
        urgent: false
      };
    }
  }

  /**
   * Calcula estadísticas rápidas para mostrar en el dashboard
   */
  calculateQuickStats(passwords: PasswordAnalysis[]): {
    criticalIssues: number;
    averageStrength: number;
    breachedPasswords: number;
    strongPasswords: number;
  } {
    if (passwords.length === 0) {
      return {
        criticalIssues: 0,
        averageStrength: 0,
        breachedPasswords: 0,
        strongPasswords: 0
      };
    }

    const breachedPasswords = passwords.filter(p => p.breach_info.is_breached).length;
    const strongPasswords = passwords.filter(p => 
      p.strength.level === 'strong' || p.strength.level === 'very_strong'
    ).length;
    const weakPasswords = passwords.filter(p => 
      p.strength.level === 'weak' || p.strength.level === 'very_weak'
    ).length;
    const oldPasswords = passwords.filter(p => p.age_days > 365).length;

    const criticalIssues = breachedPasswords + weakPasswords + Math.floor(oldPasswords / 2);
    const averageStrength = passwords.reduce((sum, p) => sum + p.strength.score, 0) / passwords.length;

    return {
      criticalIssues,
      averageStrength: Math.round(averageStrength),
      breachedPasswords,
      strongPasswords
    };
  }
}

export const securityService = new SecurityService();