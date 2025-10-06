import React from 'react';
import { Settings as Cog, Download, Upload } from 'lucide-react';
import { useUnifiedTheme } from '../../UnifiedThemeProvider';
import type { SettingsState } from '../../../pages/SettingsPage';

interface Props {
  settings: SettingsState;
  onChange: (key: keyof SettingsState, value: string | boolean) => void;
}

export const AdvancedSettings: React.FC<Props> = ({ settings, onChange }) => {
  const { colors } = useUnifiedTheme();

  return (
    <div className="settings-section settings-section-gray" style={{ backgroundColor: colors.surface }}>
      <div className="settings-section-header" style={{ borderColor: colors.border }}>
        <h2 className="settings-section-title" style={{ color: colors.textPrimary }}>
          <div className="settings-section-icon">
            <Cog className="w-4 h-4" />
          </div>
          Configuración Avanzada
        </h2>
      </div>

      <div className="settings-section-content">
        <div className="settings-content-group">
          <h3 className="settings-label" style={{ color: colors.textPrimary }}>
            Exportar / Importar datos
          </h3>
          <p className="settings-helper-text" style={{ color: colors.textMuted, marginBottom: '1rem' }}>
            Exporta tus datos para hacer una copia de seguridad o importa un backup anterior. 
            Esta funcionalidad se implementará en el backend.
          </p>
          <div className="settings-button-group">
            <button
              type="button"
              className="settings-button settings-button-primary"
              style={{ backgroundColor: colors.primary, color: 'white' }}
              onClick={() => alert('Exportar - acción mock')}
            >
              <Download className="w-4 h-4" />
              Exportar datos
            </button>
            <button
              type="button"
              className="settings-button settings-button-secondary"
              style={{ 
                border: `2px solid ${colors.border}`, 
                backgroundColor: colors.background, 
                color: colors.textPrimary 
              }}
              onClick={() => alert('Importar - acción mock')}
            >
              <Upload className="w-4 h-4" />
              Importar backup
            </button>
          </div>
        </div>

        <div className="settings-divider" style={{ backgroundColor: colors.border }} />

        <div className="settings-content-group">
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
                Habilitar logs avanzados
              </span>
              <p className="settings-checkbox-description" style={{ color: colors.textMuted }}>
                Registra eventos extendidos del sistema para diagnóstico detallado. Ten en cuenta que esto aumentará el uso de almacenamiento.
              </p>
            </div>
          </label>
        </div>

        <div className="settings-divider" style={{ backgroundColor: colors.border }} />

        <div className="settings-content-group">
          <div 
            style={{ 
              padding: '1rem',
              borderRadius: '0.5rem',
              backgroundColor: colors.background,
              border: `1px solid ${colors.border}`
            }}
          >
            <p style={{ 
              fontSize: '0.75rem', 
              color: colors.textMuted,
              margin: 0,
              lineHeight: '1.5'
            }}>
              ⚠️ <strong style={{ color: colors.textPrimary }}>Precaución:</strong> Estas opciones son para usuarios avanzados. Modificarlas incorrectamente puede afectar el funcionamiento de la aplicación.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};
export default AdvancedSettings;