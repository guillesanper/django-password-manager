import React from 'react';
import { type ActiveSession } from '../../pages/SettingsPage';
import { LogOut } from 'lucide-react';
import { useUnifiedTheme } from '../UnifiedThemeProvider';

interface Props {
  sessions: ActiveSession[];
  onTerminateSession: (id: string) => void;
  onTerminateAllOther: () => void;
}

export const SessionManagement: React.FC<Props> = ({ sessions, onTerminateSession, onTerminateAllOther }) => {
  const { colors } = useUnifiedTheme();

  return (
    <div className="settings-sessions-container" style={{ backgroundColor: colors.surface }}>
      <div className="settings-sessions-header" style={{ borderColor: colors.border }}>
        <h3 className="settings-sessions-title" style={{ color: colors.textPrimary }}>
          <div className="settings-sessions-icon">
            <LogOut className="w-4 h-4" />
          </div>
          Sesiones Activas
        </h3>
      </div>
      <div className="settings-sessions-content">
        {sessions.map(session => (
          <div 
            key={session.id} 
            className={`settings-session-item ${session.current ? 'settings-session-item-current' : ''}`}
            style={{ borderColor: session.current ? '#10b981' : colors.border }}
          >
            <div className="settings-session-header">
              <div className="settings-session-device" style={{ color: colors.textPrimary }}>
                {session.device}
                {session.current && (
                  <span className="settings-session-badge">Actual</span>
                )}
              </div>
            </div>
            <div className="settings-session-details" style={{ color: colors.textSecondary }}>
              {session.location} • Última actividad: {session.lastActive}
            </div>
            {!session.current && (
              <div className="settings-session-actions">
                <button
                  type="button"
                  onClick={() => onTerminateSession(session.id)}
                  className="settings-session-button settings-session-button-danger"
                  style={{ 
                    backgroundColor: colors.surface,
                    borderColor: colors.border,
                    color: colors.textPrimary
                  }}
                >
                  Cerrar sesión
                </button>
              </div>
            )}
          </div>
        ))}
        {sessions.length > 1 && (
          <div className="settings-button-group" style={{ marginTop: '1rem' }}>
            <button
              type="button"
              onClick={onTerminateAllOther}
              className="settings-session-button settings-session-button-danger"
              style={{ 
                width: '100%',
                backgroundColor: colors.surface,
                borderColor: '#ef4444',
                color: '#ef4444',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                gap: '0.5rem'
              }}
            >
              <LogOut className="w-4 h-4" />
              Cerrar todas excepto esta
            </button>
          </div>
        )}
      </div>
    </div>
  );
};