// src/components/theme/index.ts
// Este archivo centraliza todas las exportaciones del sistema de temas

// Provider y hooks
export { 
  ThemeProvider, 
  useTheme, 
  useThemeClasses 
} from './ThemeProvider';

// Tipos del provider
export type { 
  ThemeName, 
  ThemeColors 
} from './ThemeProvider';

// Componentes wrapper y específicos
export {
  ThemedButton,
  ThemedSurface,
  ThemedText,
  ThemedInput,
  ThemeSelector,
  SidebarButton,
  useThemedClasses
} from './ThemeComponents';

// Tipos de componentes
export type {
  ButtonVariant,
  SurfaceVariant,
  TextVariant,
  SidebarIconColor
} from './ThemeComponents';