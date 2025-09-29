import React from 'react';
import { Lock } from 'lucide-react';
import { useUnifiedTheme } from '../../../theme/UnifiedThemeProvider';
import type { SettingsState } from '../../../pages/SettingsPage';

interface Props {
  settings: SettingsState;
  onChange: (key: keyof SettingsState, value: string | boolean) => void;
}

export const PrivacySettings: React.FC<Props> = ({ settings, onChange }) => {
  const { colors } = useUnifiedTheme();

  return (
    <div className="rounded-lg shadow-md" style={{ backgroundColor: colors.surface }}>
      <div className="px-6 py-4 border-b" style={{ borderColor: colors.border }}>
        <h2 className="text-lg font-semibold flex items-center" style={{ color: colors.textPrimary }}>
          <Lock className="w-5 h-5 mr-2" />
          Privacidad
        </h2>
      </div>

      <div className="p-6 space-y-4">
        <label className="flex items-start">
          <input
            type="checkbox"
            checked={Boolean(settings.perfilPublico)}
            onChange={(e) => onChange('perfilPublico', e.target.checked)}
            className="mt-0.5 mr-3"
            style={{ accentColor: colors.primary }}
          />
          <div>
            <span className="text-sm font-medium" style={{ color: colors.textPrimary }}>
              Perfil público
            </span>
            <p className="text-xs mt-1" style={{ color: colors.textMuted }}>
              Si está activo, otros usuarios verán tu perfil básico.
            </p>
          </div>
        </label>

        <label className="flex items-start">
          <input
            type="checkbox"
            checked={Boolean(settings.compartirDatos)}
            onChange={(e) => onChange('compartirDatos', e.target.checked)}
            className="mt-0.5 mr-3"
            style={{ accentColor: colors.primary }}
          />
          <div>
            <span className="text-sm font-medium" style={{ color: colors.textPrimary }}>
              Compartir datos anónimos
            </span>
            <p className="text-xs mt-1" style={{ color: colors.textMuted }}>
              Enviar métricas anónimas para mejorar el servicio.
            </p>
          </div>
        </label>

        <label className="flex items-start">
          <input
            type="checkbox"
            checked={Boolean(settings.logsActividades)}
            onChange={(e) => onChange('logsActividades', e.target.checked)}
            className="mt-0.5 mr-3"
            style={{ accentColor: colors.primary }}
          />
          <div>
            <span className="text-sm font-medium" style={{ color: colors.textPrimary }}>
              Guardar logs de actividad
            </span>
            <p className="text-xs mt-1" style={{ color: colors.textMuted }}>
              Permite revisar acciones de cuenta en caso de problemas.
            </p>
          </div>
        </label>
      </div>
    </div>
  );
};
export default PrivacySettings;
