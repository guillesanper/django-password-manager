// useThemeDetection.ts
import { useState, useEffect } from 'react';

// Hook para detectar preferencia de tema del sistema
export const useThemeDetection = () => {
  const [isDark, setIsDark] = useState(false);

  useEffect(() => {
    const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)');
    setIsDark(mediaQuery.matches);

    const handler = (e: MediaQueryListEvent) => setIsDark(e.matches);
    mediaQuery.addEventListener('change', handler);
    
    return () => mediaQuery.removeEventListener('change', handler);
  }, []);

  return { isDark, toggleTheme: () => setIsDark(!isDark) };
};

// Colores basados en el tema
export const getThemeColors = (isDark: boolean) => ({
  background: isDark ? '#0f172a' : '#f8fafc',
  surface: isDark ? '#1e293b' : '#ffffff',
  surfaceHover: isDark ? '#334155' : '#f1f5f9',
  textPrimary: isDark ? '#f8fafc' : '#0f172a',
  textSecondary: isDark ? '#cbd5e1' : '#374151',
  textMuted: isDark ? '#94a3b8' : '#6b7280',
  border: isDark ? '#334155' : '#e2e8f0',
  primary: '#6366f1',
  primaryHover: '#4f46e5',
  success: '#10b981',
  error: '#ef4444',
  warning: '#f59e0b'
});