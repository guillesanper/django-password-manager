import React from 'react';
import { Shield } from 'lucide-react';
import { useUnifiedTheme } from '../../UnifiedThemeProvider';
import type { SettingsState, ActiveSession } from '../../../pages/SettingsPage';
import { SessionManagement } from '../SessionManagement';

interface Props {
  settings: SettingsState;
  onChange: (key: keyof SettingsState, value: string | boolean) => void;
  sessions: ActiveSession[];
  onTerminateSession: (id: string) => void;
  onTerminateAllOther: () => void;
}

export const SecuritySettings: React.FC<Props> = ({
  settings,
  onChange,
  sessions,
  onTerminateSession,
  onTerminateAllOther
}) => {
  const { colors } = useUnifiedTheme();

  return (
    <div className="settings-sections-group">
      <div className="settings-section settings-section-emerald" style={{ backgroundColor: colors.surface }}>
        <div className="settings-section-header" style={{ borderColor: colors.border }}>
          <h2 className="settings-section-title" style={{ color: colors.textPrimary }}>
            <div className="settings-section-icon">
              <Shield className="w-4 h-4" />
            </div>
            Configuración de Seguridad
          </h2>
        </div>

        <div className="settings-section-content">
          <div className="settings-content-group">
            <div className="settings-field">
              <label className="settings-label" style={{ color: colors.textPrimary }}>
                Cambiar contraseña
              </label>
              <input
                type="password"
                value={String(settings.contrasena || '')}
                onChange={(e) => onChange('contrasena', e.target.value)}
                className="settings-input"
                style={{ 
                  backgroundColor: colors.surface, 
                  borderColor: colors.border, 
                  color: colors.textPrimary 
                }}
                placeholder="Nueva contraseña"
              />
              <p className="settings-helper-text" style={{ color: colors.textMuted }}>
                Introduce una contraseña segura con al menos 8 caracteres
              </p>
            </div>
          </div>

          <div className="settings-divider" style={{ backgroundColor: colors.border }} />

          <div className="settings-content-group">
            <div className="settings-field">
              <label className="settings-label" style={{ color: colors.textPrimary }}>
                Tiempo de inactividad para cerrar sesión
              </label>
              <p className="settings-helper-text" style={{ color: colors.textMuted }}>
                (En este mock sólo mostramos la opción; implementar en backend para aplicar)
              </p>
            </div>
          </div>
        </div>
      </div>

      <SessionManagement
        sessions={sessions}
        onTerminateSession={onTerminateSession}
        onTerminateAllOther={onTerminateAllOther}
      />
    </div>
  );
};
export default SecuritySettings;