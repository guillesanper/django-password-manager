// components/auth/UnifiedAuthComponents.tsx
import React from 'react';
import { Eye, EyeOff, AlertCircle, Sun, Moon, Monitor, XCircle } from 'lucide-react';
import { useUnifiedTheme } from './UnifiedThemeProvider';

// Interfaces
export interface FormData {
  email: string;
  password: string;
  confirmPassword?: string;
  firstName?: string;
  lastName?: string;
}

interface InputFieldProps {
  label: string;
  type: string;
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
  icon?: React.ComponentType<{ className?: string }>;
  error?: string;
  showPasswordToggle?: boolean;
  onTogglePassword?: () => void;
  showPassword?: boolean;
  required?: boolean;
}

interface AuthButtonProps {
  children: React.ReactNode;
  onClick: () => void;
  loading?: boolean;
  variant?: 'primary' | 'secondary';
  disabled?: boolean;
}

interface ThemeToggleProps {
  className?: string;
}

// Componente de toggle de tema mejorado
export const ThemeToggle: React.FC<ThemeToggleProps> = ({ className = '' }) => {
  const { themeMode, setThemeMode, isDarkMode, systemPrefersDark } = useUnifiedTheme();

  const getNextMode = (): string => {
    switch (themeMode) {
      case 'system':
        return isDarkMode ? 'light' : 'dark';
      case 'light':
        return 'dark';
      case 'dark':
        return 'system';
      default:
        return 'system';
    }
  };

  const handleToggle = () => {
    const nextMode = getNextMode();
    setThemeMode(nextMode as any);
  };

  const getIcon = () => {
    switch (themeMode) {
      case 'light':
        return <Sun className="w-5 h-5" />;
      case 'dark':
        return <Moon className="w-5 h-5" />;
      case 'system':
      default:
        return <Monitor className="w-5 h-5" />;
    }
  };

  const getTooltip = () => {
    switch (themeMode) {
      case 'light':
        return 'Tema claro';
      case 'dark':
        return 'Tema oscuro';
      case 'system':
        return `Sistema (${systemPrefersDark ? 'oscuro' : 'claro'})`;
      default:
        return 'Tema del sistema';
    }
  };

  return (
    <button
      onClick={handleToggle}
      title={getTooltip()}
      className={`p-2 rounded-lg transition-colors duration-200 bg-[var(--color-surface)] border border-[var(--color-border)] text-[var(--color-text-secondary)] hover:bg-[var(--color-surface-hover)] hover:text-[var(--color-text-primary)] ${className}`}
    >
      {getIcon()}
    </button>
  );
};

// Componente de campo de entrada mejorado con mejor manejo de errores
export const InputField: React.FC<InputFieldProps> = ({ 
  label, 
  type, 
  value, 
  onChange, 
  placeholder, 
  icon: Icon, 
  error,
  showPasswordToggle,
  onTogglePassword,
  showPassword,
  required = false
}) => {
  const { colors } = useUnifiedTheme();

  return (
    <div className="space-y-2">
      <label className="block text-sm font-medium text-[var(--color-text-primary)]">
        {label} {required && <span className="text-[var(--color-error)]">*</span>}
      </label>
      <div className="relative">
        {Icon && (
          <Icon className={`absolute left-3 top-3 w-5 h-5 transition-colors duration-200 ${
            error ? 'text-[var(--color-error)]' : 'text-[var(--color-text-muted)]'
          }`} />
        )}
        <input
          type={showPasswordToggle ? (showPassword ? 'text' : 'password') : type}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          placeholder={placeholder}
          className={`w-full ${Icon ? 'pl-10' : 'pl-4'} ${showPasswordToggle ? 'pr-12' : 'pr-4'} py-3 rounded-lg border transition-all duration-200 focus:outline-none focus:ring-2 focus:border-transparent bg-[var(--color-surface)] text-[var(--color-text-primary)] placeholder-[var(--color-text-muted)] ${
            error 
              ? 'border-[var(--color-error)] ring-2 ring-[var(--color-error)] ring-opacity-20 focus:ring-[var(--color-error)]' 
              : 'border-[var(--color-border)] focus:ring-[var(--color-primary)] focus:border-[var(--color-primary)]'
          }`}
        />
        {showPasswordToggle && (
          <button
            type="button"
            onClick={onTogglePassword}
            className="absolute right-3 top-3 p-1 rounded-md transition-colors text-[var(--color-text-muted)] hover:text-[var(--color-text-primary)] focus:outline-none focus:ring-2 focus:ring-[var(--color-primary)] focus:ring-offset-1"
          >
            {showPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
          </button>
        )}
      </div>
      {error && (
        <div className="flex items-center space-x-2 animate-in slide-in-from-left-1 duration-200">
          <AlertCircle className="w-4 h-4 text-[var(--color-error)] flex-shrink-0" />
          <span className="text-sm text-[var(--color-error)]">{error}</span>
        </div>
      )}
    </div>
  );
};

// Componente de botón mejorado con estados de carga
export const AuthButton: React.FC<AuthButtonProps> = ({ 
  children, 
  onClick, 
  loading = false, 
  variant = 'primary',
  disabled = false 
}) => {
  const isPrimary = variant === 'primary';
  const isDisabled = disabled || loading;
  
  return (
    <button
      onClick={onClick}
      disabled={isDisabled}
      className={`w-full py-4 px-6 rounded-xl font-semibold text-base flex items-center justify-center space-x-2 transition-all duration-200 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-[var(--color-primary)] disabled:cursor-not-allowed transform
        ${isPrimary
          ? `border-0 shadow-lg ${isDisabled ? 'opacity-50' : 'hover:scale-[1.02] hover:shadow-xl'}`
          : `bg-transparent border-2 border-[var(--color-primary)] text-[var(--color-primary)] ${isDisabled ? 'opacity-50' : 'hover:bg-[var(--color-primary)] hover:text-[var(--color-primary-text)]'}`}
      `}
      style={isPrimary
        ? {
            background: isDisabled ? 'var(--color-text-muted)' : 'var(--color-primary)',
            color: 'var(--color-primary-text)',
          }
        : {}}
    >
      {loading ? (
        <>
          <div className="animate-spin rounded-full h-5 w-5 border-2 border-transparent border-t-current"></div>
          <span>Procesando...</span>
        </>
      ) : (
        children
      )}
    </button>
  );
};

// Componente de container de autenticación mejorado
interface AuthContainerProps {
  children: React.ReactNode;
  title: string;
  subtitle: string;
  icon: React.ReactNode;
}

export const AuthContainer: React.FC<AuthContainerProps> = ({
  children,
  title,
  subtitle,
  icon
}) => {
  return (
    <div className="min-h-screen flex items-center justify-center p-4 bg-[var(--color-background)]">
      <div className="max-w-md w-full space-y-8">
        {/* Toggle de tema */}
        <div className="flex justify-end">
          <ThemeToggle />
        </div>

        {/* Header */}
        <div className="text-center">
          <div className="flex items-center justify-center mb-6">
            {icon}
          </div>
          <h2 className="text-3xl font-bold text-[var(--color-text-primary)]">
            {title}
          </h2>
          <p className="mt-2 text-sm text-[var(--color-text-secondary)]">
            {subtitle}
          </p>
        </div>

        {/* Form Container */}
        <div className="p-8 rounded-2xl shadow-xl border bg-[var(--color-surface)] border-[var(--color-border)]">
          {children}
        </div>

        {/* Footer */}
        <div className="text-center text-xs text-[var(--color-text-muted)]">
          <p>© 2024 PasswordManager. Tus datos están protegidos con encriptación de nivel empresarial.</p>
        </div>
      </div>
    </div>
  );
};

// Componente para mostrar errores de API mejorado
interface ApiErrorProps {
  error: string;
}

export const ApiError: React.FC<ApiErrorProps> = ({ error }) => {
  if (!error) return null;
  
  return (
    <div className="p-4 rounded-lg border-l-4 bg-[var(--color-error)]/5 border-[var(--color-error)] animate-in slide-in-from-top-1 duration-300">
      <div className="flex items-center space-x-2">
        <XCircle className="w-5 h-5 text-[var(--color-error)] flex-shrink-0" />
        <p className="text-sm text-[var(--color-error)] font-medium">
          {error}
        </p>
      </div>
    </div>
  );
};

// Componente para información adicional mejorado
interface InfoBoxProps {
  children: React.ReactNode;
  icon?: React.ReactNode;
  variant?: 'info' | 'success' | 'warning';
}

export const InfoBox: React.FC<InfoBoxProps> = ({ children, icon, variant = 'info' }) => {
  const getVariantClasses = () => {
    switch (variant) {
      case 'success':
        return 'bg-[var(--color-success)]/5 border-[var(--color-success)] text-[var(--color-success)]';
      case 'warning':
        return 'bg-[var(--color-warning)]/5 border-[var(--color-warning)] text-[var(--color-warning)]';
      case 'info':
      default:
        return 'bg-[var(--color-primary)]/5 border-[var(--color-primary)] text-[var(--color-primary)]';
    }
  };

  return (
    <div className={`p-4 rounded-lg border-l-4 ${getVariantClasses()}`}>
      <div className="flex items-start">
        {icon && (
          <div className="mr-3 mt-0.5">
            {icon}
          </div>
        )}
        <div className="text-sm text-[var(--color-text-secondary)]">
          {children}
        </div>
      </div>
    </div>
  );
};

// Componente para enlaces de navegación mejorado
interface AuthLinkProps {
  text: string;
  linkText: string;
  onClick: () => void;
}

export const AuthLink: React.FC<AuthLinkProps> = ({ text, linkText, onClick }) => {
  return (
    <div className="pt-6 mt-8 border-t border-[var(--color-border)] text-center">
      <span className="text-sm text-[var(--color-text-secondary)]">
        {text}{' '}
        <button
          onClick={onClick}
          className="font-medium text-[var(--color-primary)] hover:underline transition-colors focus:outline-none focus:ring-2 focus:ring-[var(--color-primary)] focus:ring-offset-2 rounded px-1"
          type="button"
        >
          {linkText}
        </button>
      </span>
    </div>
  );
};