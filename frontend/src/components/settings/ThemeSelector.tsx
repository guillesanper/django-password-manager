import React from 'react';
import { Sun, Moon, Monitor } from 'lucide-react';
import { useUnifiedTheme } from '../../theme/UnifiedThemeProvider';

interface Props {
  theme: string;
  onChange: (theme: string) => void;
}

export const ThemeSelector: React.FC<Props> = ({ theme, onChange }) => {
  const { colors } = useUnifiedTheme();

  const themes = [
    { id: 'light', name: 'Claro', icon: <Sun className="w-5 h-5" /> },
    { id: 'dark', name: 'Oscuro', icon: <Moon className="w-5 h-5" /> },
    { id: 'system', name: 'Sistema', icon: <Monitor className="w-5 h-5" /> },
  ];

  return (
    <div className="flex space-x-4">
      {themes.map(t => (
        <button
          key={t.id}
          onClick={() => onChange(t.id)}
          className={`flex items-center px-4 py-2 rounded-md border ${
            theme === t.id ? 'font-bold' : ''
          }`}
          style={{
            borderColor: colors.border,
            backgroundColor: theme === t.id ? colors.primary : colors.surface,
            color: theme === t.id ? colors.primary : colors.textPrimary,
          }}
        >
          {t.icon}
          <span className="ml-2">{t.name}</span>
        </button>
      ))}
    </div>
  );
};
