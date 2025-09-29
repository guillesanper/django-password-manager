import React from 'react';
import { Shield } from 'lucide-react';
import { useUnifiedTheme } from '../../../theme/UnifiedThemeProvider';
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
    <div className="space-y-6">
      <div className="rounded-lg shadow-md" style={{ backgroundColor: colors.surface }}>
        <div className="px-6 py-4 border-b" style={{ borderColor: colors.border }}>
          <h2 className="text-lg font-semibold flex items-center" style={{ color: colors.textPrimary }}>
            <Shield className="w-5 h-5 mr-2" />
            Configuración de Seguridad
          </h2>
        </div>

        <div className="p-6 space-y-4">
          <div>
            <h3 className="text-sm font-medium" style={{ color: colors.textPrimary }}>
              Cambiar contraseña
            </h3>
            <div className="mt-2">
              <label className="block text-xs mb-1" style={{ color: colors.textMuted }}>Nueva contraseña</label>
              <input
                type="password"
                value={String(settings.contrasena || '')}
                onChange={(e) => onChange('contrasena', e.target.value)}
                className="w-full px-3 py-2 border rounded-md"
                style={{ backgroundColor: colors.surface, borderColor: colors.border, color: colors.textPrimary }}
              />
            </div>
          </div>

          <div>
            <label className="block text-sm font-medium mb-2" style={{ color: colors.textPrimary }}>
              Tiempo de inactividad para cerrar sesión (gestión simplificada)
            </label>
            <p className="text-xs" style={{ color: colors.textMuted }}>
              (En este mock sólo mostramos la opción; implementar en backend para aplicar)
            </p>
          </div>
        </div>
      </div>

      {/* Session management - reuse component */}
      <SessionManagement
        sessions={sessions}
        onTerminateSession={onTerminateSession}
        onTerminateAllOther={onTerminateAllOther}
      />
    </div>
  );
};
export default SecuritySettings;
