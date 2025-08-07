import React, { useState, useEffect, createContext, useContext } from 'react';

// Definición de tipos para los temas
export type ThemeName = 'light' | 'dark' | 'pink' | 'blue' | 'purple';

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
    background: '#ffffff',
    backgroundSecondary: '#f9fafb',
    backgroundTertiary: '#f3f4f6',
    surface: '#ffffff',
    surfaceHover: '#f9fafb',
    textPrimary: '#111827',
    textSecondary: '#374151',
    textMuted: '#6b7280',
    border: '#e5e7eb',
    borderHover: '#d1d5db',
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
    primary: '#8b5cf6',
    primaryHover: '#7c3aed',
    primaryText: '#ffffff',
    secondary: '#374151',
    secondaryHover: '#4b5563',
    secondaryText: '#d1d5db',
    background: '#111827',
    backgroundSecondary: '#1f2937',
    backgroundTertiary: '#374151',
    surface: '#1f2937',
    surfaceHover: '#374151',
    textPrimary: '#f9fafb',
    textSecondary: '#d1d5db',
    textMuted: '#9ca3af',
    border: '#374151',
    borderHover: '#4b5563',
    success: '#10b981',
    warning: '#f59e0b',
    error: '#ef4444',
    info: '#3b82f6',
    sidebarBg: '#1f2937',
    sidebarText: '#d1d5db',
    sidebarHover: '#374151',
    sidebarActive: '#374151',
    headerBg: '#1f2937',
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
    backgroundSecondary: '#fce7f3',
    backgroundTertiary: '#fbcfe8',
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
    backgroundSecondary: '#e0f2fe',
    backgroundTertiary: '#bae6fd',
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
    backgroundSecondary: '#f3e8ff',
    backgroundTertiary: '#e9d5ff',
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

// Context del tema
interface ThemeContextType {
  theme: ThemeName;
  colors: ThemeColors;
  setTheme: (theme: ThemeName) => void;
  availableThemes: ThemeName[];
}

const ThemeContext = createContext<ThemeContextType | undefined>(undefined);

// Hook personalizado para usar el tema
export const useTheme = (): ThemeContextType => {
  const context = useContext(ThemeContext);
  if (context === undefined) {
    throw new Error('useTheme must be used within a ThemeProvider');
  }
  return context;
};

// Función para aplicar variables CSS
const applyThemeVariables = (colors: ThemeColors): void => {
  const root = document.documentElement;
  
  Object.entries(colors).forEach(([key, value]) => {
    // Convertir camelCase a kebab-case para CSS custom properties
    const cssVar = `--color-${key.replace(/([A-Z])/g, '-$1').toLowerCase()}`;
    root.style.setProperty(cssVar, value);
  });
};

// Provider del tema mejorado
export const ThemeProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [theme, setThemeState] = useState<ThemeName>(() => {
    // Intentar obtener el tema guardado (sin localStorage por restricciones del ambiente)
    return 'light';
  });

  const setTheme = (newTheme: ThemeName): void => {
    setThemeState(newTheme);
    // Aquí podrías agregar localStorage si estuvieras en un ambiente que lo soporte
    // localStorage.setItem('app-theme', newTheme);
  };

  // Aplicar variables CSS cuando cambie el tema
  useEffect(() => {
    const colors = themes[theme];
    applyThemeVariables(colors);
    
    // También aplicar clase de tema para Tailwind
    const root = document.documentElement;
    Object.keys(themes).forEach(t => root.classList.remove(t));
    root.classList.add(theme);
  }, [theme]);

  const contextValue: ThemeContextType = {
    theme,
    colors: themes[theme],
    setTheme,
    availableThemes: Object.keys(themes) as ThemeName[],
  };

  return (
    <ThemeContext.Provider value={contextValue}>
      {children}
    </ThemeContext.Provider>
  );
};

// Hook adicional para obtener clases de Tailwind basadas en el tema actual
export const useThemeClasses = () => {
  useTheme();
  
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