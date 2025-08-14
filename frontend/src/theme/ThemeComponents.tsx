import React from 'react';
import { useTheme, useThemeClasses } from './ThemeProvider';

// Tipos para las variantes de componentes
export type ButtonVariant = 'primary' | 'secondary' | 'success' | 'warning' | 'error' | 'ghost';
export type SurfaceVariant = 'primary' | 'secondary' | 'elevated';
export type TextVariant = 'primary' | 'secondary' | 'muted';
export type SidebarIconColor = 'indigo' | 'emerald' | 'amber' | 'purple' | 'blue' | 'rose' | 'gray';

// ============= COMPONENTES WRAPPER =============

// Button wrapper con temas
interface ThemedButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  size?: 'sm' | 'md' | 'lg';
  fullWidth?: boolean;
  children: React.ReactNode;
}

export const ThemedButton: React.FC<ThemedButtonProps> = ({
  variant = 'primary',
  size = 'md',
  fullWidth = false,
  className = '',
  children,
  ...props
}) => {
  
  const baseClasses = 'inline-flex items-center justify-center rounded-lg font-medium transition-all duration-200 focus:outline-none focus:ring-2 focus:ring-offset-2';
  
  const sizeClasses = {
    sm: 'px-3 py-1.5 text-sm',
    md: 'px-4 py-2 text-sm',
    lg: 'px-6 py-3 text-base',
  };
  
  const variantClasses = {
    primary: `bg-[var(--color-primary)] hover:bg-[var(--color-primary-hover)] text-[var(--color-primary-text)] focus:ring-[var(--color-primary)]`,
    secondary: `bg-[var(--color-secondary)] hover:bg-[var(--color-secondary-hover)] text-[var(--color-secondary-text)] focus:ring-[var(--color-primary)]`,
    success: `bg-[var(--color-success)] hover:bg-green-600 text-white focus:ring-[var(--color-success)]`,
    warning: `bg-[var(--color-warning)] hover:bg-yellow-600 text-white focus:ring-[var(--color-warning)]`,
    error: `bg-[var(--color-error)] hover:bg-red-600 text-white focus:ring-[var(--color-error)]`,
    ghost: `bg-transparent hover:bg-[var(--color-surface-hover)] text-[var(--color-text-primary)] border border-[var(--color-border)] hover:border-[var(--color-border-hover)]`,
  };
  
  const widthClass = fullWidth ? 'w-full' : '';
  
  const combinedClasses = `${baseClasses} ${sizeClasses[size]} ${variantClasses[variant]} ${widthClass} ${className}`;
  
  return (
    <button className={combinedClasses} {...props}>
      {children}
    </button>
  );
};

// Card/Surface wrapper con temas
interface ThemedSurfaceProps extends React.HTMLAttributes<HTMLDivElement> {
  variant?: SurfaceVariant;
  padding?: 'none' | 'sm' | 'md' | 'lg';
  rounded?: boolean;
  shadow?: boolean;
  border?: boolean;
  children: React.ReactNode;
}

export const ThemedSurface: React.FC<ThemedSurfaceProps> = ({
  variant = 'primary',
  padding = 'md',
  rounded = true,
  shadow = true,
  border = true,
  className = '',
  children,
  ...props
}) => {
  const baseClasses = 'transition-all duration-200';
  
  const variantClasses = {
    primary: 'bg-[var(--color-surface)] hover:bg-[var(--color-surface-hover)]',
    secondary: 'bg-[var(--color-background-secondary)]',
    elevated: 'bg-[var(--color-surface)] hover:bg-[var(--color-surface-hover)]',
  };
  
  const paddingClasses = {
    none: '',
    sm: 'p-3',
    md: 'p-4',
    lg: 'p-6',
  };
  
  const roundedClass = rounded ? 'rounded-lg' : '';
  const shadowClass = shadow ? 'shadow-sm hover:shadow-md' : '';
  const borderClass = border ? 'border border-[var(--color-border)]' : '';
  
  const combinedClasses = `${baseClasses} ${variantClasses[variant]} ${paddingClasses[padding]} ${roundedClass} ${shadowClass} ${borderClass} ${className}`;
  
  return (
    <div className={combinedClasses} {...props}>
      {children}
    </div>
  );
};

// Text wrapper con temas
interface ThemedTextProps extends React.HTMLAttributes<HTMLElement> {
  variant?: TextVariant;
  size?: 'xs' | 'sm' | 'md' | 'lg' | 'xl' | '2xl';
  weight?: 'normal' | 'medium' | 'semibold' | 'bold';
  as?: 'p' | 'span' | 'div' | 'h1' | 'h2' | 'h3' | 'h4' | 'h5' | 'h6' | 'label';
  children: React.ReactNode;
}

export const ThemedText: React.FC<ThemedTextProps> = ({
  variant = 'primary',
  size = 'md',
  weight = 'normal',
  as: Component = 'p',
  className = '',
  children,
  ...props
}) => {
  const variantClasses = {
    primary: 'text-[var(--color-text-primary)]',
    secondary: 'text-[var(--color-text-secondary)]',
    muted: 'text-[var(--color-text-muted)]',
  };
  
  const sizeClasses = {
    xs: 'text-xs',
    sm: 'text-sm',
    md: 'text-base',
    lg: 'text-lg',
    xl: 'text-xl',
    '2xl': 'text-2xl',
  };
  
  const weightClasses = {
    normal: 'font-normal',
    medium: 'font-medium',
    semibold: 'font-semibold',
    bold: 'font-bold',
  };
  
  const combinedClasses = `${variantClasses[variant]} ${sizeClasses[size]} ${weightClasses[weight]} ${className}`;
  
  return (
    <Component className={combinedClasses} {...props}>
      {children}
    </Component>
  );
};

// Input wrapper con temas
interface ThemedInputProps extends React.InputHTMLAttributes<HTMLInputElement> {
  label?: string;
  error?: string;
  helperText?: string;
}

export const ThemedInput: React.FC<ThemedInputProps> = ({
  label,
  error,
  helperText,
  className = '',
  ...props
}) => {
  const inputClasses = `
    w-full px-3 py-2 rounded-lg transition-colors duration-200
    bg-[var(--color-surface)] 
    border border-[var(--color-border)] 
    text-[var(--color-text-primary)]
    placeholder-[var(--color-text-muted)]
    focus:outline-none focus:ring-2 focus:ring-[var(--color-primary)] focus:border-transparent
    ${error ? 'border-[var(--color-error)] focus:ring-[var(--color-error)]' : ''}
    ${className}
  `;
  
  return (
    <div className="space-y-1">
      {label && (
        <ThemedText as="label" variant="primary" size="sm" weight="medium">
          {label}
        </ThemedText>
      )}
      <input className={inputClasses} {...props} />
      {error && (
        <ThemedText variant="primary" size="sm" className="text-[var(--color-error)]">
          {error}
        </ThemedText>
      )}
      {helperText && !error && (
        <ThemedText variant="muted" size="sm">
          {helperText}
        </ThemedText>
      )}
    </div>
  );
};

// Select de temas
interface ThemeSelectorProps {
  className?: string;
}

export const ThemeSelector: React.FC<ThemeSelectorProps> = ({ className = '' }) => {
  const { theme, setTheme, availableThemes } = useTheme();
  
  const themeLabels: Record<string, string> = {
    light: '☀️ Claro',
    dark: '🌙 Oscuro',
    pink: '🌸 Rosa',
    blue: '🌊 Azul',
    purple: '💜 Púrpura',
  };
  
  return (
    <div className={`space-y-2 ${className}`}>
      <ThemedText variant="primary" size="sm" weight="medium">
        Tema de la aplicación
      </ThemedText>
      <select
        value={theme}
        onChange={(e) => setTheme(e.target.value as any)}
        className="
          w-full px-3 py-2 rounded-lg transition-colors duration-200
          bg-[var(--color-surface)] 
          border border-[var(--color-border)] 
          text-[var(--color-text-primary)]
          focus:outline-none focus:ring-2 focus:ring-[var(--color-primary)] focus:border-transparent
        "
      >
        {availableThemes.map((themeName) => (
          <option key={themeName} value={themeName}>
            {themeLabels[themeName] || themeName}
          </option>
        ))}
      </select>
    </div>
  );
};

// ============= COMPONENTE ESPECÍFICO PARA BOTONES DEL SIDEBAR =============

interface SidebarButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  isActive?: boolean;
  iconColor?: SidebarIconColor;
  icon: React.ReactNode;
  children: React.ReactNode;
}

export const SidebarButton: React.FC<SidebarButtonProps> = ({
  isActive = false,
  iconColor = 'gray',
  icon,
  children,
  className = '',
  ...props
}) => {
  // Construir las clases CSS completas
  const baseClass = 'sidebar-button';
  const activeClass = isActive ? 'active' : '';
  const colorClass = iconColor;
  
  const buttonClasses = `${baseClass} ${activeClass} ${colorClass} ${className}`;
  const iconClasses = `sidebar-icon ${iconColor}`;
  
  return (
    <button className={buttonClasses} {...props}>
      <span className={iconClasses}>
        {icon}
      </span>
      {children}
    </button>
  );
};

// ============= HOOK PARA CLASES COMBINADAS MEJORADO =============

export const useThemedClasses = () => {
  
  return {
    // Sidebar específico - MEJORADO
    sidebarContainer: 'sidebar-container',
    
    sidebarButton: (isActive: boolean = false, iconColor: SidebarIconColor = 'gray') => {
      const base = 'sidebar-button';
      const active = isActive ? 'active' : '';
      return `${base} ${active} ${iconColor}`.trim();
    },
    
    sidebarIcon: (iconColor: SidebarIconColor = 'gray') => `sidebar-icon ${iconColor}`,
    
    sidebarNavGroup: 'sidebar-nav-group',
    
    sidebarGroupTitle: 'sidebar-group-title',
    
    sidebarSeparator: 'sidebar-separator',
    
    // Header específico
    headerButton: `
      p-2 rounded-lg transition-colors duration-200
      text-[var(--color-header-text)]
      hover:bg-[var(--color-sidebar-hover)]
    `,
    
    // Card con hover
    interactiveCard: `
      p-4 rounded-lg border transition-all duration-200 cursor-pointer
      bg-[var(--color-surface)] 
      border-[var(--color-border)]
      hover:bg-[var(--color-surface-hover)]
      hover:border-[var(--color-border-hover)]
      hover:shadow-md
    `,
    
    // Divisor
    divider: `
      border-t border-[var(--color-border)]
    `,
    
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