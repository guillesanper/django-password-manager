import React from 'react';
import { Lock } from 'lucide-react';
import { useUnifiedTheme } from '../../UnifiedThemeProvider';
import type { SettingsState } from '../../../pages/SettingsPage';

interface Props {
  settings: SettingsState;
  onChange: (key: keyof SettingsState, value: string | boolean) => void;
}

export const PrivacySettings: React.FC<Props> = ({ settings, onChange }) => {
  const { colors } = useUnifiedTheme();

  return (
    <div className="settings-section settings-section-rose" style={{ backgroundColor: colors.surface }}>
      <div className="settings-section-header" style={{ borderColor: colors.border }}>
        <h2 className="settings-section-title" style={{ color: colors.textPrimary }}>
          <div className="settings-section-icon">
            <Lock className="w-4 h-4" />
          </div>
          Privacidad
        </h2>
      </div>

      <div className="settings-section-content">
        <div className="settings-content-group">
          <label className="settings-checkbox-group">
            <input
              type="checkbox"
              checked={Boolean(settings.perfilPublico)}
              onChange={(e) => onChange('perfilPublico', e.target.checked)}
              className="settings-checkbox"
              style={{ accentColor: colors.primary }}
            />
            <div className="settings-checkbox-content">
              <span className="settings-checkbox-label" style={{ color: colors.textPrimary }}>
                Perfil público
              </span>
              <p className="settings-checkbox-description" style={{ color: colors.textMuted }}>
                Si está activo, otros usuarios verán tu perfil básico.
              </p>
            </div>
          </label>

          <label className="settings-checkbox-group">
            <input
              type="checkbox"
              checked={Boolean(settings.compartirDatos)}
              onChange={(e) => onChange('compartirDatos', e.target.checked)}
              className="settings-checkbox"
              style={{ accentColor: colors.primary }}
            />
            <div className="settings-checkbox-content">
              <span className="settings-checkbox-label" style={{ color: colors.textPrimary }}>
                Compartir datos anónimos
              </span>
              <p className="settings-checkbox-description" style={{ color: colors.textMuted }}>
                Enviar métricas anónimas para mejorar el servicio.
              </p>
            </div>
          </label>

          <label className="settings-checkbox-group">
            <input
              type="checkbox"
              checked={Boolean(settings.logsActividades)}
              onChange={(e) => onChange('logsActividades', e.target.checked)}
              className="settings-checkbox"
              style={{ accentColor: colors.primary }}
            />
            <div className="settings-checkbox-content">
              <span className="settings-checkbox-label" style={{ color: colors.textPrimary }}>
                Guardar logs de actividad
              </span>
              <p className="settings-checkbox-description" style={{ color: colors.textMuted }}>
                Permite revisar acciones de cuenta en caso de problemas.
              </p>
            </div>
          </label>
        </div>
      </div>
    </div>
  );
};
export default PrivacySettings;