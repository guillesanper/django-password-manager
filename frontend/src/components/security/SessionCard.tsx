import React, { useState } from 'react';
import { 
  Monitor, 
  MapPin, 
  AlertOctagon, 
  Clock, 
  ChevronRight, 
  LogOut, 
  RefreshCw 
} from 'lucide-react';
import { sessionService, type Session } from '../../services/sessionService';
import '../../styles/security.css';


interface SessionCardProps {
  session: Session;
  onTerminate: (sessionId: string) => void;
  onFlag: (sessionId: string) => void;
  isTerminating: boolean;
}

export const SessionCard: React.FC<SessionCardProps> = ({ 
  session, 
  onTerminate, 
  onFlag,
  isTerminating 
}) => {
  const [showDetails, setShowDetails] = useState(false);

  const getSecurityLevelBadge = () => {
    const level = session.security_level || 'medium';
    const labels = {
      compromised: 'Comprometida',
      low: 'Riesgo Bajo',
      medium: 'Normal',
      high: 'Segura'
    };

    const badgeClass = level === 'high' ? 'secure' : 
                       level === 'medium' ? 'normal' : 
                       level === 'low' ? 'warning' : 'danger';

    return (
      <span className={`security-session-badge ${session.is_current ? 'current' : badgeClass}`}>
        {session.is_current ? 'Sesión actual' : labels[level]}
      </span>
    );
  };

  return (
    <div className="security-session-card">
      {/* Header */}
      <div className="security-session-header">
        <div className="security-session-info">
          <div className="security-session-browser">
            <span className="text-2xl">{sessionService.getDeviceIcon(session.device_info)}</span>
            <h3>{session.device_info.browser}</h3>
          </div>
          <p className="security-session-os">
            {session.device_info.os}
          </p>
        </div>
        {getSecurityLevelBadge()}
      </div>

      {/* Información básica */}
      <div className="security-session-details">
        <div className="security-session-detail-item">
          <MapPin className="security-session-detail-icon" />
          <span>
            {session.location.city}, {session.location.country}
          </span>
        </div>
        <div className="security-session-detail-item">
          <Monitor className="security-session-detail-icon" />
          <span>IP: {session.ip_address}</span>
        </div>
        <div className="security-session-detail-item">
          <Clock className="security-session-detail-icon" />
          <span>
            Última actividad: {sessionService.formatTimeAgo(session.last_activity)}
          </span>
        </div>
      </div>

      {/* Alertas de seguridad */}
      {session.security_analysis && session.security_analysis.alerts.length > 0 && (
        <div className="security-session-alerts">
          {session.security_analysis.alerts.map((alert, idx) => {
            const alertClass = alert.severity === 'high' ? 'alert-danger' : 
                             alert.severity === 'medium' ? 'alert-warning' : 'alert-info';
            return (
              <div key={idx} className={`security-session-alert ${alertClass}`}>
                <AlertOctagon className="security-session-alert-icon" />
                <span>{alert.message}</span>
              </div>
            );
          })}
        </div>
      )}

      {/* Detalles expandibles */}
      {showDetails && (
        <div className="security-session-expanded-details">
          <div className="security-session-stats-grid">
            <div className="security-session-stat">
              <div className="security-session-stat-label">Duración:</div>
              <div className="security-session-stat-value">{session.duration_minutes} min</div>
            </div>
            <div className="security-session-stat">
              <div className="security-session-stat-label">Actividades:</div>
              <div className="security-session-stat-value">{session.activities_count}</div>
            </div>
            <div className="security-session-stat">
              <div className="security-session-stat-label">Score:</div>
              <div className="security-session-stat-value">{session.security_score}/100</div>
            </div>
            <div className="security-session-stat">
              <div className="security-session-stat-label">Creada:</div>
              <div className="security-session-stat-value">
                {sessionService.formatTimeAgo(session.created_at)}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Acciones */}
      <div className="security-session-actions">
        <button
          onClick={() => setShowDetails(!showDetails)}
          className="security-session-button security-session-button-details"
        >
          <ChevronRight
            className={`security-session-button-icon ${showDetails ? 'rotate-90' : ''}`}
            style={{ transition: 'transform 0.3s' }}
          />
          {showDetails ? 'Ocultar' : 'Ver'} detalles
        </button>
        
        {!session.is_current && (
          <>
            {session.security_analysis?.is_suspicious && (
              <button
                onClick={() => onFlag(session.session_id)}
                className="security-session-button security-session-button-warning"
              >
                <AlertOctagon className="security-session-button-icon" />
                Marcar
              </button>
            )}
            <button
              onClick={() => onTerminate(session.session_id)}
              disabled={isTerminating}
              className="security-session-button security-session-button-danger"
            >
              {isTerminating ? (
                <RefreshCw className="security-session-button-icon security-session-button-spinner" />
              ) : (
                <LogOut className="security-session-button-icon" />
              )}
              Cerrar
            </button>
          </>
        )}
      </div>
    </div>
  );
};