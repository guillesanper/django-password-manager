import React from 'react';
import { Bell } from 'lucide-react';
import { useUnifiedTheme } from '../../../theme/UnifiedThemeProvider';
import type { SettingsState } from '../../../pages/SettingsPage';

interface Props {
  settings: SettingsState;
  onChange: (key: keyof SettingsState, value: string | boolean) => void;
}

export const NotificationSettings: React.FC<Props> = ({ settings, onChange }) => {
  const { colors } = useUnifiedTheme();

  return (
    <div className="rounded-lg shadow-md" style={{ backgroundColor: colors.surface }}>
      <div className="px-6 py-4 border-b" style={{ borderColor: colors.border }}>
        <h2 className="text-lg font-semibold flex items-center" style={{ color: colors.textPrimary }}>
          <Bell className="w-5 h-5 mr-2" />
          Configuración de Notificaciones
        </h2>
      </div>

      <div className="p-6 space-y-4">
        <label className="flex items-start">
          <input
            type="checkbox"
            checked={Boolean(settings.notificacionesEmail)}
            onChange={(e) => onChange('notificacionesEmail', e.target.checked)}
            className="mt-0.5 mr-3"
            style={{ accentColor: colors.primary }}
          />
          <div>
            <span className="text-sm font-medium" style={{ color: colors.textPrimary }}>
              Notificaciones por correo
            </span>
            <p className="text-xs mt-1" style={{ color: colors.textMuted }}>
              Recibe alertas importantes y resúmenes por email.
            </p>
          </div>
        </label>

        <label className="flex items-start">
          <input
            type="checkbox"
            checked={Boolean(settings.notificacionesSMS)}
            onChange={(e) => onChange('notificacionesSMS', e.target.checked)}
            className="mt-0.5 mr-3"
            style={{ accentColor: colors.primary }}
          />
          <div>
            <span className="text-sm font-medium" style={{ color: colors.textPrimary }}>
              Notificaciones por SMS
            </span>
            <p className="text-xs mt-1" style={{ color: colors.textMuted }}>
              Mensajes SMS para alertas críticas.
            </p>
          </div>
        </label>
      </div>
    </div>
  );
};
export default NotificationSettings;
