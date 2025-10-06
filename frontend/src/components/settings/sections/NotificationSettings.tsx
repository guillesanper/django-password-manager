import React from 'react';
import { Bell } from 'lucide-react';
import { useUnifiedTheme } from '../../UnifiedThemeProvider';
import type { SettingsState } from '../../../pages/SettingsPage';

interface Props {
  settings: SettingsState;
  onChange: (key: keyof SettingsState, value: string | boolean) => void;
}

export const NotificationSettings: React.FC<Props> = ({ settings, onChange }) => {
  const { colors } = useUnifiedTheme();

  return (
    <div className="settings-section settings-section-amber" style={{ backgroundColor: colors.surface }}>
      <div className="settings-section-header" style={{ borderColor: colors.border }}>
        <h2 className="settings-section-title" style={{ color: colors.textPrimary }}>
          <div className="settings-section-icon">
            <Bell className="w-4 h-4" />
          </div>
          Configuración de Notificaciones
        </h2>
      </div>

      <div className="settings-section-content">
        <div className="settings-content-group">
          <label className="settings-checkbox-group">
            <input
              type="checkbox"
              checked={Boolean(settings.notificacionesEmail)}
              onChange={(e) => onChange('notificacionesEmail', e.target.checked)}
              className="settings-checkbox"
              style={{ accentColor: colors.primary }}
            />
            <div className="settings-checkbox-content">
              <span className="settings-checkbox-label" style={{ color: colors.textPrimary }}>
                Notificaciones por correo
              </span>
              <p className="settings-checkbox-description" style={{ color: colors.textMuted }}>
                Recibe alertas importantes y resúmenes por email.
              </p>
            </div>
          </label>

          <label className="settings-checkbox-group">
            <input
              type="checkbox"
              checked={Boolean(settings.notificacionesSMS)}
              onChange={(e) => onChange('notificacionesSMS', e.target.checked)}
              className="settings-checkbox"
              style={{ accentColor: colors.primary }}
            />
            <div className="settings-checkbox-content">
              <span className="settings-checkbox-label" style={{ color: colors.textPrimary }}>
                Notificaciones por SMS
              </span>
              <p className="settings-checkbox-description" style={{ color: colors.textMuted }}>
                Mensajes SMS para alertas críticas.
              </p>
            </div>
          </label>
        </div>
      </div>
    </div>
  );
};
export default NotificationSettings;