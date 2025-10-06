// components/theme/UnifiedThemeProvider.tsx
import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';

// Tipos unificados
export type ThemeName = 'light' | 'dark' | 'pink' | 'blue' | 'purple';
export type ThemeMode = 'system' | 'light' | 'dark';

export interface ThemeColors {
  // Colores principales
  primary: string;
  primaryHover: string;
  primaryText: string;
  
  // Colores secundarios
  secondary: string;
  secondaryHover: string;
  secondaryText: string;
  
  // Colores de fondo
  background: string;
  backgroundSecondary: string;
  backgroundTertiary: string;
  
  // Colores de superficie (cards, modales, etc.)
  surface: string;
  surfaceHover: string;
  
  // Colores de texto
  textPrimary: string;
  textSecondary: string;
  textMuted: string;
  
  // Colores de borde
  border: string;
  borderHover: string;
  
  // Estados
  success: string;
  warning: string;
  error: string;
  info: string;
  
  // Colores específicos del sidebar
  sidebarBg: string;
  sidebarText: string;
  sidebarHover: string;
  sidebarActive: string;
  
  // Header
  headerBg: string;
  headerText: string;
  headerBorder: string;
}

// Definición de temas con sus colores
export const themes: Record<ThemeName, ThemeColors> = {
  light: {
    primary: '#6366f1',
    primaryHover: '#4f46e5',
    primaryText: '#ffffff',
    secondary: '#f3f4f6',
    secondaryHover: '#e5e7eb',
    secondaryText: '#374151',
    background: '#f8fafc',
    backgroundSecondary: '#ffffff',
    backgroundTertiary: '#f3f4f6',
    surface: '#ffffff',
    surfaceHover: '#f9fafb',
    textPrimary: '#0f172a',
    textSecondary: '#374151',
    textMuted: '#64748b',
    border: '#e2e8f0',
    borderHover: '#cbd5e1',
    success: '#10b981',
    warning: '#f59e0b',
    error: '#ef4444',
    info: '#3b82f6',
    sidebarBg: '#ffffff',
    sidebarText: '#4b5563',
    sidebarHover: '#f3f4f6',
    sidebarActive: '#f3f4f6',
    headerBg: '#ffffff',
    headerText: '#374151',
    headerBorder: '#e5e7eb',
  },
  dark: {
    primary: '#6366f1',
    primaryHover: '#4f46e5',
    primaryText: '#ffffff',
    secondary: '#374151',
    secondaryHover: '#4b5563',
    secondaryText: '#d1d5db',
    background: '#0f172a',
    backgroundSecondary: '#1e293b',
    backgroundTertiary: '#334155',
    surface: '#1e293b',
    surfaceHover: '#334155',
    textPrimary: '#f8fafc',
    textSecondary: '#cbd5e1',
    textMuted: '#94a3b8',
    border: '#334155',
    borderHover: '#475569',
    success: '#10b981',
    warning: '#f59e0b',
    error: '#ef4444',
    info: '#3b82f6',
    sidebarBg: '#1e293b',
    sidebarText: '#d1d5db',
    sidebarHover: '#374151',
    sidebarActive: '#374151',
    headerBg: '#1e293b',
    headerText: '#d1d5db',
    headerBorder: '#374151',
  },
  pink: {
    primary: '#ec4899',
    primaryHover: '#db2777',
    primaryText: '#ffffff',
    secondary: '#fce7f3',
    secondaryHover: '#fbcfe8',
    secondaryText: '#831843',
    background: '#fdf2f8',
    backgroundSecondary: '#ffffff',
    backgroundTertiary: '#fce7f3',
    surface: '#ffffff',
    surfaceHover: '#fdf2f8',
    textPrimary: '#831843',
    textSecondary: '#9d174d',
    textMuted: '#be185d',
    border: '#f9a8d4',
    borderHover: '#f472b6',
    success: '#10b981',
    warning: '#f59e0b',
    error: '#ef4444',
    info: '#3b82f6',
    sidebarBg: '#ffffff',
    sidebarText: '#9d174d',
    sidebarHover: '#fce7f3',
    sidebarActive: '#fce7f3',
    headerBg: '#ffffff',
    headerText: '#9d174d',
    headerBorder: '#f9a8d4',
  },
  blue: {
    primary: '#3b82f6',
    primaryHover: '#2563eb',
    primaryText: '#ffffff',
    secondary: '#dbeafe',
    secondaryHover: '#bfdbfe',
    secondaryText: '#1e40af',
    background: '#f0f9ff',
    backgroundSecondary: '#ffffff',
    backgroundTertiary: '#e0f2fe',
    surface: '#ffffff',
    surfaceHover: '#f0f9ff',
    textPrimary: '#0c4a6e',
    textSecondary: '#0369a1',
    textMuted: '#0284c7',
    border: '#7dd3fc',
    borderHover: '#38bdf8',
    success: '#10b981',
    warning: '#f59e0b',
    error: '#ef4444',
    info: '#3b82f6',
    sidebarBg: '#ffffff',
    sidebarText: '#0369a1',
    sidebarHover: '#e0f2fe',
    sidebarActive: '#e0f2fe',
    headerBg: '#ffffff',
    headerText: '#0369a1',
    headerBorder: '#7dd3fc',
  },
  purple: {
    primary: '#8b5cf6',
    primaryHover: '#7c3aed',
    primaryText: '#ffffff',
    secondary: '#ede9fe',
    secondaryHover: '#ddd6fe',
    secondaryText: '#5b21b6',
    background: '#faf5ff',
    backgroundSecondary: '#ffffff',
    backgroundTertiary: '#f3e8ff',
    surface: '#ffffff',
    surfaceHover: '#faf5ff',
    textPrimary: '#581c87',
    textSecondary: '#6b21a8',
    textMuted: '#7c3aed',
    border: '#c4b5fd',
    borderHover: '#a78bfa',
    success: '#10b981',
    warning: '#f59e0b',
    error: '#ef4444',
    info: '#3b82f6',
    sidebarBg: '#ffffff',
    sidebarText: '#6b21a8',
    sidebarHover: '#f3e8ff',
    sidebarActive: '#f3e8ff',
    headerBg: '#ffffff',
    headerText: '#6b21a8',
    headerBorder: '#c4b5fd',
  },
};

// Context del tema unificado
interface UnifiedThemeContextType {
  // Configuración actual
  themeMode: ThemeMode;
  themeName: ThemeName;
  isDarkMode: boolean;
  colors: ThemeColors;
  
  // Funciones para cambiar tema
  setThemeMode: (mode: ThemeMode) => void;
  setThemeName: (name: ThemeName) => void;
  toggleTheme: () => void;
  
  // Datos adicionales
  availableThemes: ThemeName[];
  systemPrefersDark: boolean;
}

const UnifiedThemeContext = createContext<UnifiedThemeContextType | undefined>(undefined);

// Hook para usar el tema unificado
export const useUnifiedTheme = (): UnifiedThemeContextType => {
  const context = useContext(UnifiedThemeContext);
  if (context === undefined) {
    throw new Error('useUnifiedTheme must be used within a UnifiedThemeProvider');
  }
  return context;
};

// Función para detectar preferencia del sistema SIN efecto flash
const getSystemThemePreference = (): boolean => {
  if (typeof window === 'undefined') return false;
  return window.matchMedia('(prefers-color-scheme: dark)').matches;
};

// Función para aplicar variables CSS de forma síncrona
const applyThemeVariables = (colors: ThemeColors): void => {
  const root = document.documentElement;
  
  // Aplicar variables CSS
  Object.entries(colors).forEach(([key, value]) => {
    const cssVar = `--color-${key.replace(/([A-Z])/g, '-$1').toLowerCase()}`;
    root.style.setProperty(cssVar, value);
  });
};

// Función para aplicar tema inicial ANTES del primer render
const initializeTheme = (): { isDarkMode: boolean; themeName: ThemeName; themeMode: ThemeMode } => {
  const systemPrefersDark = getSystemThemePreference();
  
  // Por ahora usamos valores por defecto, pero podrías usar localStorage aquí
  const themeMode: ThemeMode = 'system';
  const themeName: ThemeName = 'light'; // Tema base
  const isDarkMode = themeMode === 'system' ? systemPrefersDark : themeMode === 'dark';
  
  // Determinar el tema final
  const finalTheme = isDarkMode ? 'dark' : themeName;
  const colors = themes[finalTheme as ThemeName];
  
  // Aplicar inmediatamente
  applyThemeVariables(colors);
  
  return { isDarkMode, themeName, themeMode };
};

// Provider del tema unificado
export const UnifiedThemeProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  // Inicializar estado con tema del sistema para evitar flash
  const [state, setState] = useState(() => initializeTheme());
  const [systemPrefersDark, setSystemPrefersDark] = useState(() => getSystemThemePreference());

  // Función para determinar si debe usar tema oscuro
  const shouldUseDarkMode = useCallback((mode: ThemeMode, systemDark: boolean): boolean => {
    switch (mode) {
      case 'dark':
        return true;
      case 'light':
        return false;
      case 'system':
      default:
        return systemDark;
    }
  }, []);

  // Función para obtener los colores finales
  const getFinalColors = useCallback((themeName: ThemeName, isDark: boolean): ThemeColors => {
    if (isDark && themeName === 'light') {
      return themes.dark;
    }
    return themes[themeName];
  }, []);

  // Efecto para escuchar cambios en la preferencia del sistema
  useEffect(() => {
    const mediaQuery = window.matchMedia('(prefers-color-scheme: dark)');
    
    const handleChange = (e: MediaQueryListEvent) => {
      const newSystemPrefersDark = e.matches;
      setSystemPrefersDark(newSystemPrefersDark);
      
      // Solo actualizar si estamos en modo sistema
      if (state.themeMode === 'system') {
        const newIsDarkMode = shouldUseDarkMode('system', newSystemPrefersDark);
        const newColors = getFinalColors(state.themeName, newIsDarkMode);
        
        setState(prev => ({ ...prev, isDarkMode: newIsDarkMode }));
        applyThemeVariables(newColors);
      }
    };

    mediaQuery.addEventListener('change', handleChange);
    return () => mediaQuery.removeEventListener('change', handleChange);
  }, [state.themeMode, state.themeName, shouldUseDarkMode, getFinalColors]);

  // Función para cambiar el modo de tema (system/light/dark)
  const setThemeMode = useCallback((mode: ThemeMode) => {
    const newIsDarkMode = shouldUseDarkMode(mode, systemPrefersDark);
    const newColors = getFinalColors(state.themeName, newIsDarkMode);
    
    setState(prev => ({ ...prev, themeMode: mode, isDarkMode: newIsDarkMode }));
    applyThemeVariables(newColors);
  }, [systemPrefersDark, state.themeName, shouldUseDarkMode, getFinalColors]);

  // Función para cambiar el nombre del tema (light/pink/blue/purple)
  const setThemeName = useCallback((name: ThemeName) => {
    const newColors = getFinalColors(name, state.isDarkMode);
    
    setState(prev => ({ ...prev, themeName: name }));
    applyThemeVariables(newColors);
  }, [state.isDarkMode, getFinalColors]);

  // Función para toggle rápido entre claro/oscuro
  const toggleTheme = useCallback(() => {
    const newMode: ThemeMode = state.isDarkMode ? 'light' : 'dark';
    setThemeMode(newMode);
  }, [state.isDarkMode, setThemeMode]);

  // Calcular colores actuales
  const currentColors = getFinalColors(state.themeName, state.isDarkMode);

  const contextValue: UnifiedThemeContextType = {
    themeMode: state.themeMode,
    themeName: state.themeName,
    isDarkMode: state.isDarkMode,
    colors: currentColors,
    setThemeMode,
    setThemeName,
    toggleTheme,
    availableThemes: Object.keys(themes) as ThemeName[],
    systemPrefersDark,
  };

  return (
    <UnifiedThemeContext.Provider value={contextValue}>
      {children}
    </UnifiedThemeContext.Provider>
  );
};

// Hook para obtener clases de CSS basadas en el tema actual
export const useThemeClasses = () => {
  
  return {
    // Clases base para diferentes elementos
    background: {
      primary: 'bg-[var(--color-background)]',
      secondary: 'bg-[var(--color-background-secondary)]',
      tertiary: 'bg-[var(--color-background-tertiary)]',
    },
    text: {
      primary: 'text-[var(--color-text-primary)]',
      secondary: 'text-[var(--color-text-secondary)]',
      muted: 'text-[var(--color-text-muted)]',
    },
    surface: {
      default: 'bg-[var(--color-surface)] hover:bg-[var(--color-surface-hover)]',
      border: 'border-[var(--color-border)] hover:border-[var(--color-border-hover)]',
    },
    button: {
      primary: 'bg-[var(--color-primary)] hover:bg-[var(--color-primary-hover)] text-[var(--color-primary-text)]',
      secondary: 'bg-[var(--color-secondary)] hover:bg-[var(--color-secondary-hover)] text-[var(--color-secondary-text)]',
    },
    sidebar: {
      background: 'bg-[var(--color-sidebar-bg)]',
      text: 'text-[var(--color-sidebar-text)]',
      hover: 'hover:bg-[var(--color-sidebar-hover)]',
      active: 'bg-[var(--color-sidebar-active)]',
    },
    header: {
      background: 'bg-[var(--color-header-bg)]',
      text: 'text-[var(--color-header-text)]',
      border: 'border-[var(--color-header-border)]',
    },
    // Estados
    states: {
      success: 'text-[var(--color-success)]',
      warning: 'text-[var(--color-warning)]',
      error: 'text-[var(--color-error)]',
      info: 'text-[var(--color-info)]',
    }
  };
};