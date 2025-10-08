import React, { useState } from 'react';
import { 
  AlertTriangle, 
  CheckCircle, 
  Eye, 
  Shield,
  RefreshCw,
  ChevronRight
} from 'lucide-react';
import { useUnifiedTheme } from '../UnifiedThemeProvider';
import { type PasswordAnalysis, securityService } from '../../services/securityService';
import { StrengthProgressBar } from './StrengthProgressBar';

interface PasswordCardProps {
  password: PasswordAnalysis;
  onCheckBreach: (passwordId: number) => void;
  onViewPassword: (passwordId: number) => void;
  isBreachChecking: boolean;
}

export const PasswordCard: React.FC<PasswordCardProps> = ({ 
  password, 
  onCheckBreach, 
  onViewPassword,
  isBreachChecking 
}) => {
  const { colors } = useUnifiedTheme();
  const [showDetails, setShowDetails] = useState(false);

  const getAgeColor = (days: number) => {
    if (days > 730) return colors.error;
    if (days > 365) return colors.warning;
    if (days > 180) return colors.info;
    return colors.success;
  };

  const formatAge = (days: number) => {
    if (days > 365) {
      const years = Math.floor(days / 365);
      return `${years} año${years > 1 ? 's' : ''}`;
    } else if (days > 30) {
      const months = Math.floor(days / 30);
      return `${months} mes${months > 1 ? 'es' : ''}`;
    } else {
      return `${days} día${days > 1 ? 's' : ''}`;
    }
  };

  return (
    <div className="security-password-card">
      {/* Header con información básica */}
      <div className="security-password-card-header">
        <div className="security-password-card-info">
          <div className="security-password-card-title">
            <span>{password.website}</span>
            {password.breach_info.is_breached && (
              <AlertTriangle className="w-4 h-4" style={{ color: colors.error }} />
            )}
          </div>
          <p className="security-password-card-username">
            {password.username}
          </p>
          <span 
            className="security-password-card-age"
            style={{ 
              backgroundColor: getAgeColor(password.age_days) + '20',
              color: getAgeColor(password.age_days)
            }}
          >
            Creada hace {formatAge(password.age_days)}
          </span>
        </div>
        
        <button
          onClick={() => setShowDetails(!showDetails)}
          className={`security-password-card-toggle ${showDetails ? 'active' : ''}`}
        >
          <ChevronRight className="security-password-card-toggle-icon" />
        </button>
      </div>

      {/* Barra de fortaleza */}
      <div className="security-password-strength-container">
        <StrengthProgressBar 
          strength={password.strength} 
          entropy={password.entropy} 
        />
      </div>

      {/* Información de breach */}
      <div className={`security-password-breach-info ${password.breach_info.is_breached ? 'breached' : 'safe'}`}>
        <div className="security-password-breach-status">
          {password.breach_info.is_breached ? (
            <AlertTriangle className="w-4 h-4" style={{ color: colors.error }} />
          ) : (
            <CheckCircle className="w-4 h-4" style={{ color: colors.success }} />
          )}
          <span style={{ color: colors.textSecondary }}>
            {password.breach_info.message}
          </span>
        </div>
        
        {password.breach_info.is_breached && (
          <span 
            className="security-password-breach-badge"
            style={{ 
              backgroundColor: colors.error + '20',
              color: colors.error
            }}
          >
            {securityService.formatBreachCount(password.breach_info.breach_count)} veces
          </span>
        )}
      </div>

      {/* Detalles expandibles */}
      {showDetails && (
        <div className="security-password-expanded">
          <div className="security-password-stats">
            <div>
              <span className="security-password-stat-label" style={{ color: colors.textSecondary }}>
                Entropía:
              </span>
              <span className="security-password-stat-value" style={{ color: colors.textPrimary }}>
                {password.entropy.toFixed(1)} bits
              </span>
            </div>
            <div>
              <span className="security-password-stat-label" style={{ color: colors.textSecondary }}>
                Puntuación:
              </span>
              <span className="security-password-stat-value" style={{ color: password.strength.color }}>
                {password.strength.score}/100
              </span>
            </div>
            <div>
              <span className="security-password-stat-label" style={{ color: colors.textSecondary }}>
                Última actualización:
              </span>
              <span className="security-password-stat-value" style={{ color: colors.textPrimary }}>
                {formatAge(password.last_updated_days)}
              </span>
            </div>
          </div>

          <div className="security-password-actions">
            <button
              onClick={() => onViewPassword(password.id)}
              className="security-password-action-button primary"
            >
              <Eye className="security-password-action-icon" />
              <span>Ver contraseña</span>
            </button>
            <button
              onClick={() => onCheckBreach(password.id)}
              disabled={isBreachChecking}
              className="security-password-action-button secondary"
            >
              {isBreachChecking ? (
                <RefreshCw className="security-password-action-icon animate-spin" />
              ) : (
                <Shield className="security-password-action-icon" />
              )}
              <span>Verificar breach</span>
            </button>
          </div>
        </div>
      )}
    </div>
  );
};