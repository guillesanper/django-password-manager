import React, { useState } from 'react';
import { Palette } from 'lucide-react';
import { useUnifiedTheme } from '../../../theme/UnifiedThemeProvider';
import { ThemeSelector } from '../ThemeSelector';

export const ThemeSettings: React.FC = () => {
  const { colors, systemPrefersDark } = useUnifiedTheme();
  const [themeChoice, setThemeChoice] = useState<string>(systemPrefersDark ? 'dark' : 'light');

  return (
    <div className="rounded-lg shadow-md" style={{ backgroundColor: colors.surface }}>
      <div className="px-6 py-4 border-b" style={{ borderColor: colors.border }}>
        <h2 className="text-lg font-semibold flex items-center" style={{ color: colors.textPrimary }}>
          <Palette className="w-5 h-5 mr-2" />
          Apariencia
        </h2>
      </div>

      <div className="p-6">
        <p className="text-sm mb-4" style={{ color: colors.textSecondary }}>
          Escoge el modo y esquema de color de la aplicación.
        </p>

        <ThemeSelector theme={themeChoice} onChange={setThemeChoice} />

        <div className="mt-4 text-xs" style={{ color: colors.textMuted }}>
          <p>Elección actual: <strong style={{ color: colors.textPrimary }}>{themeChoice}</strong></p>
        </div>
      </div>
    </div>
  );
};
export default ThemeSettings;
