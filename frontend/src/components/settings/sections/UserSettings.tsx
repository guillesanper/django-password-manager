import React from 'react';
import { User } from 'lucide-react';
import { useUnifiedTheme } from '../../../theme/UnifiedThemeProvider';
import type { SettingsState } from '../../../pages/SettingsPage';

interface Props {
  settings: SettingsState;
  onChange: (key: keyof SettingsState, value: string | boolean) => void;
}

export const UserSettings: React.FC<Props> = ({ settings, onChange }) => {
  const { colors } = useUnifiedTheme();

  return (
    <div className="rounded-lg shadow-md" style={{ backgroundColor: colors.surface }}>
      <div className="px-6 py-4 border-b" style={{ borderColor: colors.border }}>
        <h2 className="text-lg font-semibold flex items-center" style={{ color: colors.textPrimary }}>
          <User className="w-5 h-5 mr-2" />
          Información Personal
        </h2>
      </div>

      <div className="p-6 space-y-4">
        <div>
          <label className="block text-sm font-medium mb-2" style={{ color: colors.textPrimary }}>
            Nombre para mostrar
          </label>
          <input
            type="text"
            value={settings.nombre}
            onChange={(e) => onChange('nombre', e.target.value)}
            className="w-full px-3 py-2 border rounded-md"
            style={{ backgroundColor: colors.surface, borderColor: colors.border, color: colors.textPrimary }}
          />
        </div>

        <div>
          <label className="block text-sm font-medium mb-2" style={{ color: colors.textPrimary }}>
            Correo electrónico
          </label>
          <input
            type="email"
            value={settings.correo}
            onChange={(e) => onChange('correo', e.target.value)}
            className="w-full px-3 py-2 border rounded-md"
            style={{ backgroundColor: colors.surface, borderColor: colors.border, color: colors.textPrimary }}
          />
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <label className="block text-sm font-medium mb-2" style={{ color: colors.textPrimary }}>
              Idioma
            </label>
            <select
              value={settings.idioma}
              onChange={(e) => onChange('idioma', e.target.value)}
              className="w-full px-3 py-2 border rounded-md"
              style={{ backgroundColor: colors.surface, borderColor: colors.border, color: colors.textPrimary }}
            >
              <option value="es">Español</option>
              <option value="en">English</option>
              <option value="fr">Français</option>
            </select>
          </div>

          <div>
            <label className="block text-sm font-medium mb-2" style={{ color: colors.textPrimary }}>
              Zona horaria
            </label>
            <select
              value={settings.zonaHoraria}
              onChange={(e) => onChange('zonaHoraria', e.target.value)}
              className="w-full px-3 py-2 border rounded-md"
              style={{ backgroundColor: colors.surface, borderColor: colors.border, color: colors.textPrimary }}
            >
              <option value="Europe/Madrid">Madrid (Europe/Madrid)</option>
              <option value="Europe/London">Londres (Europe/London)</option>
              <option value="America/New_York">Nueva York (America/New_York)</option>
            </select>
          </div>
        </div>
      </div>
    </div>
  );
};
export default UserSettings;
