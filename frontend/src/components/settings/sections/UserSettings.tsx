import React from 'react';
import { User } from 'lucide-react';
import { useUnifiedTheme } from '../../UnifiedThemeProvider';
import type { SettingsState } from '../../../pages/SettingsPage';

interface Props {
  settings: SettingsState;
  onChange: (key: keyof SettingsState, value: string | boolean) => void;
}

export const UserSettings: React.FC<Props> = ({ settings, onChange }) => {
  const { colors } = useUnifiedTheme();

  return (
    <div className="settings-section settings-section-indigo" style={{ backgroundColor: colors.surface }}>
      <div className="settings-section-header" style={{ borderColor: colors.border }}>
        <h2 className="settings-section-title" style={{ color: colors.textPrimary }}>
          <div className="settings-section-icon">
            <User className="w-4 h-4" />
          </div>
          Información Personal
        </h2>
      </div>

      <div className="settings-section-content">
        <div className="settings-content-group">
          <div className="settings-field">
            <label className="settings-label" style={{ color: colors.textPrimary }}>
              Nombre para mostrar
            </label>
            <input
              type="text"
              value={settings.nombre}
              onChange={(e) => onChange('nombre', e.target.value)}
              className="settings-input"
              style={{ 
                backgroundColor: colors.surface, 
                borderColor: colors.border, 
                color: colors.textPrimary 
              }}
              placeholder="Ingresa tu nombre"
            />
          </div>

          <div className="settings-field">
            <label className="settings-label" style={{ color: colors.textPrimary }}>
              Correo electrónico
            </label>
            <input
              type="email"
              value={settings.correo}
              onChange={(e) => onChange('correo', e.target.value)}
              className="settings-input"
              style={{ 
                backgroundColor: colors.surface, 
                borderColor: colors.border, 
                color: colors.textPrimary 
              }}
              placeholder="tu@email.com"
            />
            <p className="settings-helper-text" style={{ color: colors.textMuted }}>
              Este correo se usará para notificaciones importantes
            </p>
          </div>
        </div>

        <div className="settings-divider" style={{ backgroundColor: colors.border }} />

        <div className="settings-content-group">
          <div className="settings-grid">
            <div className="settings-field">
              <label className="settings-label" style={{ color: colors.textPrimary }}>
                Idioma
              </label>
              <select
                value={settings.idioma}
                onChange={(e) => onChange('idioma', e.target.value)}
                className="password-sort-select"
                style={{ 
                  backgroundColor: colors.surface, 
                  borderColor: colors.border, 
                  color: colors.textPrimary 
                }}
              >
                <option value="es">Español</option>
                <option value="en">English</option>
                <option value="fr">Français</option>
              </select>
            </div>

            <div className="settings-field">
              <label className="settings-label" style={{ color: colors.textPrimary }}>
                Zona horaria
              </label>
              <select
                value={settings.zonaHoraria}
                onChange={(e) => onChange('zonaHoraria', e.target.value)}
                className="password-sort-select"
                style={{ 
                  backgroundColor: colors.surface, 
                  borderColor: colors.border, 
                  color: colors.textPrimary 
                }}
              >
                <option value="Europe/Madrid">Madrid (Europe/Madrid)</option>
                <option value="Europe/London">Londres (Europe/London)</option>
                <option value="America/New_York">Nueva York (America/New_York)</option>
              </select>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
export default UserSettings;