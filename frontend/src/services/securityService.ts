// services/securityService.ts
import { authService } from './authService'

import { API_BASE_URL } from '../config/api';
import { passwordService } from './passwordService';
import {
  calculatePasswordEntropy,
  getPasswordStrengthCategory,
  findDuplicatePasswords,
  analyzePasswordPatterns,
  checkPasswordBreaches,
} from './passwordAnalysis';

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

const EMPTY_ANALYSIS: SecurityAnalysis = {
  overall_score: 0,
  average_entropy: 0,
  strength_distribution: {},
  security_issues: [],
  recommendations: [],
  patterns: {
    duplicate_groups: 0,
    length_distribution: {},
    character_usage_stats: { uppercase: 0, lowercase: 0, digits: 0, special: 0 },
  },
};

class SecurityService {
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
      console.error('Security Service Error:', error);
      throw error;
    }
  }

  /**
   * Análisis completo de seguridad — ZERO-KNOWLEDGE (paso 27).
   *
   * El servidor ya no puede descifrar: se descargan las cuentas como blobs opacos, se descifran en
   * cliente (passwordService, que usa la VaultKey en memoria) y todo el análisis —entropía,
   * fortaleza, duplicados, patrones y la comprobación HIBP por k-anonimato— ocurre aquí. Las
   * entradas de bóvedas privadas bloqueadas no se pueden descifrar y quedan fuera del análisis
   * (requieren desbloquear la bóveda primero).
   */
  async getSecurityAnalysis(): Promise<SecurityAnalysisResponse> {
    try {
      const accounts = await passwordService.getAccounts();
      const decrypted = accounts.filter(
        (a) => typeof a.decrypted_password === 'string' && a.decrypted_password.length > 0,
      );
      const total = decrypted.length;

      if (total === 0) {
        return { success: true, total_passwords: 0, analysis: { ...EMPTY_ANALYSIS }, passwords: [] };
      }

      const breaches = await checkPasswordBreaches(decrypted.map((a) => a.decrypted_password as string));
      const now = Date.now();
      const DAY = 86_400_000;

      const passwords: PasswordAnalysis[] = decrypted.map((a) => {
        const pw = a.decrypted_password as string;
        const entropy = calculatePasswordEntropy(pw);
        const created = a.created_at ? new Date(a.created_at).getTime() : now;
        const updated = a.updated_at ? new Date(a.updated_at).getTime() : now;
        return {
          id: a.id,
          website: a.website,
          username: a.username,
          entropy: Math.round(entropy * 100) / 100,
          strength: getPasswordStrengthCategory(entropy),
          breach_info:
            breaches.get(pw) ?? { is_breached: false, breach_count: 0, message: 'No verificada' },
          age_days: Math.floor((now - created) / DAY),
          last_updated_days: Math.floor((now - updated) / DAY),
        };
      });

      // Agregados
      const strengthDistribution: Record<string, number> = {};
      let totalEntropy = 0;
      let breachedCount = 0;
      let oldPasswords = 0;
      let weakPasswords = 0;
      for (const p of passwords) {
        strengthDistribution[p.strength.level] = (strengthDistribution[p.strength.level] || 0) + 1;
        totalEntropy += p.entropy;
        if (p.breach_info.is_breached) breachedCount += 1;
        if (p.age_days > 365) oldPasswords += 1;
        if (p.strength.level === 'weak' || p.strength.level === 'very_weak') weakPasswords += 1;
      }

      const duplicates = findDuplicatePasswords(
        decrypted.map((a) => ({ password: a.decrypted_password as string, id: a.id })),
      );
      const duplicateGroups = Object.keys(duplicates).length;
      const duplicateCount = Object.values(duplicates).reduce((s, ids) => s + ids.length, 0);
      const patterns = analyzePasswordPatterns(decrypted.map((a) => a.decrypted_password as string));

      const avgEntropy = totalEntropy / total;
      const entropyScore = Math.min(100, (avgEntropy / 60) * 40);
      const breachScore = ((total - breachedCount) / total) * 30;
      const ageScore = ((total - oldPasswords) / total) * 20;
      const strengthScore = ((total - weakPasswords) / total) * 10;
      const overallScore = Math.round(entropyScore + breachScore + ageScore + strengthScore);

      const securityIssues: SecurityIssue[] = [];
      const recommendations: string[] = [];

      if (weakPasswords > 0) {
        securityIssues.push({
          type: 'weak_passwords',
          count: weakPasswords,
          severity: 'high',
          message: `${weakPasswords} contraseñas son débiles o muy débiles`,
        });
        recommendations.push(`Actualiza ${weakPasswords} contraseñas débiles por otras más seguras`);
      }
      if (breachedCount > 0) {
        securityIssues.push({
          type: 'breached_passwords',
          count: breachedCount,
          severity: 'critical',
          message: `${breachedCount} contraseñas encontradas en filtraciones de datos`,
        });
        recommendations.push(`Cambia inmediatamente ${breachedCount} contraseñas comprometidas`);
      }
      if (duplicateGroups > 0) {
        securityIssues.push({
          type: 'duplicate_passwords',
          count: duplicateGroups,
          severity: 'medium',
          message: `${duplicateCount} contraseñas duplicadas encontradas`,
        });
        recommendations.push('Usa contraseñas únicas para cada cuenta');
      }
      if (oldPasswords > 0) {
        securityIssues.push({
          type: 'old_passwords',
          count: oldPasswords,
          severity: 'medium',
          message: `${oldPasswords} contraseñas tienen más de 1 año`,
        });
        recommendations.push('Actualiza contraseñas antiguas regularmente');
      }
      if (recommendations.length === 0) {
        recommendations.push('¡Excelente! Tu seguridad de contraseñas está en buen estado');
      }

      return {
        success: true,
        total_passwords: total,
        analysis: {
          overall_score: overallScore,
          average_entropy: Math.round(avgEntropy * 100) / 100,
          strength_distribution: strengthDistribution,
          security_issues: securityIssues,
          recommendations,
          patterns: {
            duplicate_groups: duplicateGroups,
            length_distribution: patterns.length_distribution,
            character_usage_stats: patterns.character_usage,
          },
        },
        passwords,
      };
    } catch (error) {
      console.error('Error building security analysis:', error);
      return {
        success: false,
        total_passwords: 0,
        analysis: { ...EMPTY_ANALYSIS },
        passwords: [],
        error: error instanceof Error ? error.message : 'Error al cargar el análisis de seguridad',
      };
    }
  }

  /**
   * Recomendaciones por metadatos (endpoint vivo, no descifra nada).
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
      return { grade: 'A+', color: '#10b981', description: 'Excelente seguridad' };
    } else if (score >= 80) {
      return { grade: 'A', color: '#059669', description: 'Muy buena seguridad' };
    } else if (score >= 70) {
      return { grade: 'B', color: '#3b82f6', description: 'Buena seguridad' };
    } else if (score >= 60) {
      return { grade: 'C', color: '#f59e0b', description: 'Seguridad moderada' };
    } else if (score >= 50) {
      return { grade: 'D', color: '#f97316', description: 'Seguridad deficiente' };
    } else {
      return { grade: 'F', color: '#ef4444', description: 'Seguridad muy deficiente' };
    }
  }

  getAgeCategory(days: number): { category: string; color: string; urgent: boolean } {
    if (days > 730) {
      return { category: 'Muy antigua', color: '#dc2626', urgent: true };
    } else if (days > 365) {
      return { category: 'Antigua', color: '#ea580c', urgent: true };
    } else if (days > 180) {
      return { category: 'Moderada', color: '#d97706', urgent: false };
    } else {
      return { category: 'Reciente', color: '#059669', urgent: false };
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
      return { criticalIssues: 0, averageStrength: 0, breachedPasswords: 0, strongPasswords: 0 };
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
