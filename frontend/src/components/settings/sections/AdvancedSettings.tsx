import React from 'react';
import { Settings as Cog } from 'lucide-react';
import { useUnifiedTheme } from '../../../theme/UnifiedThemeProvider';
import type { SettingsState } from '../../../pages/SettingsPage';

interface Props {
  settings: SettingsState;
  onChange: (key: keyof SettingsState, value: string | boolean) => void;
}

export const AdvancedSettings: React.FC<Props> = ({ settings, onChange }) => {
  const { colors } = useUnifiedTheme();

  return (
    <div className="rounded-lg shadow-md" style={{ backgroundColor: colors.surface }}>
      <div className="px-6 py-4 border-b" style={{ borderColor: colors.border }}>
        <h2 className="text-lg font-semibold flex items-center" style={{ color: colors.textPrimary }}>
          <Cog className="w-5 h-5 mr-2" />
          Avanzado
        </h2>
      </div>

      <div className="p-6 space-y-4">
        <div>
          <h3 className="text-sm font-medium" style={{ color: colors.textPrimary }}>Exportar / Importar datos</h3>
          <p className="text-xs mt-1" style={{ color: colors.textMuted }}>
            Exporta tus datos o importa un backup. (Funcionalidad a implementar en backend)
          </p>
          <div className="mt-3 flex space-x-2">
            <button
              type="button"
              className="px-3 py-2 rounded-md text-sm"
              style={{ backgroundColor: colors.background, color: colors.primary }}
              onClick={() => alert('Exportar - acción mock')}
            >
              Exportar datos
            </button>
            <button
              type="button"
              className="px-3 py-2 rounded-md text-sm"
              style={{ border: `1px solid ${colors.border}`, backgroundColor: colors.background, color: colors.textPrimary }}
              onClick={() => alert('Importar - acción mock')}
            >
              Importar backup
            </button>
          </div>
        </div>

        <div>
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
                Habilitar logs avanzados
              </span>
              <p className="text-xs mt-1" style={{ color: colors.textMuted }}>
                Registra eventos extendidos para diagnóstico (aumenta uso de almacenamiento).
              </p>
            </div>
          </label>
        </div>
      </div>
    </div>
  );
};
export default AdvancedSettings;
