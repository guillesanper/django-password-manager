import React from 'react';
import { Sun, Moon, Monitor } from 'lucide-react';
import { useUnifiedTheme, type ThemeMode, type ThemeName } from '../UnifiedThemeProvider';

interface Props {
  theme: ThemeMode;
  themeName: ThemeName;
  onChange: (theme: ThemeMode) => void;
  onThemeNameChange: (name: ThemeName) => void;
}

export const ThemeSelector: React.FC<Props> = ({ theme, themeName, onChange, onThemeNameChange }) => {
  const { colors } = useUnifiedTheme();

  const themeModes = [
    { id: 'light' as ThemeMode, name: 'Claro', icon: <Sun className="w-5 h-5" /> },
    { id: 'dark' as ThemeMode, name: 'Oscuro', icon: <Moon className="w-5 h-5" /> },
    { id: 'system' as ThemeMode, name: 'Sistema', icon: <Monitor className="w-5 h-5" /> },
  ];

  const themeColors = [
    { 
      id: 'light' as ThemeName, 
      name: 'Índigo',
      colors: ['#6366f1', '#818cf8', '#c7d2fe']
    },
    { 
      id: 'pink' as ThemeName, 
      name: 'Rosa',
      colors: ['#ec4899', '#f472b6', '#fbcfe8']
    },
    { 
      id: 'blue' as ThemeName, 
      name: 'Azul',
      colors: ['#3b82f6', '#60a5fa', '#bfdbfe']
    },
    { 
      id: 'purple' as ThemeName, 
      name: 'Púrpura',
      colors: ['#8b5cf6', '#a78bfa', '#ddd6fe']
    },
  ];

  return (
    <div className="theme-selector-container" style={{ backgroundColor: colors.surface, borderColor: colors.border }}>
      {/* Modo de tema */}
      <div>
        <label className="theme-color-label" style={{ color: colors.textPrimary }}>
          Modo de visualización
        </label>
        <div className="theme-mode-buttons">
          {themeModes.map(t => (
            <button
              key={t.id}
              onClick={() => onChange(t.id)}
              className={`theme-mode-button ${theme === t.id ? 'active' : ''}`}
              style={{
                borderColor: theme === t.id ? colors.primary : colors.border,
                backgroundColor: theme === t.id ? colors.primary : colors.surface,
                color: theme === t.id ? 'white' : colors.textSecondary,
              }}
            >
              {t.icon}
              <span>{t.name}</span>
            </button>
          ))}
        </div>
      </div>

      <div className="theme-divider" style={{ background: `linear-gradient(90deg, transparent, ${colors.border}, transparent)` }} />

      {/* Paleta de colores */}
      <div>
        <label className="theme-color-label" style={{ color: colors.textPrimary }}>
          Paleta de colores
        </label>
        <div className="theme-color-grid">
          {themeColors.map(t => (
            <button
              key={t.id}
              onClick={() => onThemeNameChange(t.id)}
              className={`theme-color-option ${themeName === t.id ? 'active' : ''} theme-${t.id}`}
              style={{
                borderColor: themeName === t.id ? t.colors[0] : colors.border,
                backgroundColor: colors.surface,
              }}
            >
              <div className="theme-color-preview">
                {t.colors.map((color, index) => (
                  <div 
                    key={index}
                    className="theme-color-bar"
                    style={{ backgroundColor: color }}
                  />
                ))}
              </div>
              <span className="theme-color-name" style={{ color: themeName === t.id ? t.colors[0] : colors.textPrimary }}>
                {t.name}
              </span>
            </button>
          ))}
        </div>
      </div>

      {/* Info adicional */}
      <div className="theme-info-box" style={{ borderLeftColor: colors.primary }}>
        <p className="theme-info-text" style={{ color: colors.textSecondary }}>
          <strong style={{ color: colors.textPrimary }}>Consejo:</strong> El modo "Sistema" se ajusta automáticamente según la configuración de tu dispositivo, mientras que las paletas de colores personalizan la apariencia de la interfaz.
        </p>
      </div>
    </div>
  );
};