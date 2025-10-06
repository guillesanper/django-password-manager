import React from 'react';
import { Palette } from 'lucide-react';
import { useUnifiedTheme } from '../../UnifiedThemeProvider';
import { ThemeSelector } from '../ThemeSelector';

export const ThemeSettings: React.FC = () => {
  const { colors, themeMode, themeName, setThemeMode, setThemeName } = useUnifiedTheme();

  return (
    <div className="settings-section settings-section-purple" style={{ backgroundColor: colors.surface }}>
      <div className="settings-section-header" style={{ borderColor: colors.border }}>
        <h2 className="settings-section-title" style={{ color: colors.textPrimary }}>
          <div className="settings-section-icon">
            <Palette className="w-4 h-4" />
          </div>
          Apariencia
        </h2>
      </div>

      <div className="settings-section-content">
        <div className="settings-content-group">
          <p className="settings-helper-text" style={{ color: colors.textSecondary }}>
            Personaliza el modo de visualización y la paleta de colores de la aplicación.
          </p>

          <div className="settings-theme-selector-wrapper">
            <ThemeSelector 
              theme={themeMode}
              themeName={themeName}
              onChange={setThemeMode}
              onThemeNameChange={setThemeName}
            />
          </div>
        </div>
      </div>
    </div>
  );
};

export default ThemeSettings;