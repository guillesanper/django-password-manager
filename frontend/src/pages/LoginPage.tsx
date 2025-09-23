import React, { useState } from 'react';
import { Mail, Lock, ArrowRight, Shield } from 'lucide-react';
import { 
  InputField, 
  AuthButton, 
  AuthContainer, 
  ApiError, 
  AuthLink,
} from '../components/AuthComponents';
import type { FormData } from '../components/AuthComponents';
import { useAuth } from '../components/AuthProvider';
import { useLoginErrorHandler } from '../components/hooks/AuthErrorProvider'; // NUEVA IMPORTACIÓN

export interface LoginPageProps {
  onSwitchToRegister: () => void;
}

export const LoginPage: React.FC<LoginPageProps> = ({ 
  onSwitchToRegister
}) => {
  const { login } = useAuth();
  const { 
    loginErrors, 
    loginApiError, 
    clearLoginErrors, 
    classifyAndSetError,
    handleFieldChange,
    validateForm,
    setLoginErrors
  } = useLoginErrorHandler(); // USAR EL HOOK DE ERRORES
  
  const [formData, setFormData] = useState<FormData>({
    email: '',
    password: ''
  });
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);

  const handleSubmit = async () => {
    // Limpiar errores previos usando el contexto
    clearLoginErrors();
    
    // Validar formulario usando el hook
    const { isValid, errors } = validateForm(formData);
    
    if (!isValid) {
      setLoginErrors(errors);
      return;
    }
    
    setLoading(true);

    try {
      const result = await login({
        email: formData.email.trim(),
        password: formData.password
      });
      
      if (!result.success) {
        const errorMessage = result.error || 'Error en el inicio de sesión';
        // Usar el clasificador de errores del contexto
        classifyAndSetError(errorMessage);
      } else {
        // En caso de éxito, limpiar todos los errores
        clearLoginErrors();
      }
    } catch (error) {
      // Error de conexión
      classifyAndSetError('Error de conexión. Verifica tu conexión a internet e inténtalo de nuevo.');
    } finally {
      setLoading(false);
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !loading) {
      e.preventDefault();
      handleSubmit();
    }
  };

  const handleInputChange = (field: keyof FormData) => (value: string) => {
    // Actualizar el estado del formulario
    setFormData(prev => ({ ...prev, [field]: value }));
    
    // Manejar la lógica de limpieza de errores usando el contexto
    handleFieldChange(field, value);
  };

  const handleForgotPassword = () => {
    classifyAndSetError('Función de recuperación de contraseña próximamente disponible');
  };

  return (
    <AuthContainer
      title="PasswordManager"
      subtitle="Inicia sesión para gestionar tus contraseñas de forma segura"
      icon={
        <div className="p-3 rounded-full bg-gradient-to-r from-indigo-500 to-purple-600">
          <Shield className="w-8 h-8 text-white" />
        </div>
      }
    >
      <div className="space-y-6">
        {/* Error del API - Ahora desde el contexto */}
        {loginApiError && (
          <div className="mb-4">
            <ApiError error={loginApiError} />
          </div>
        )}

        <div onKeyDown={handleKeyDown}>
          <div className="space-y-4">
            <InputField
              label="Correo electrónico"
              type="email"
              value={formData.email}
              onChange={handleInputChange('email')}
              placeholder="tu@email.com"
              icon={Mail}
              error={loginErrors.email} // Error desde el contexto
              required
            />

            <InputField
              label="Contraseña"
              type="password"
              value={formData.password}
              onChange={handleInputChange('password')}
              placeholder="Tu contraseña"
              icon={Lock}
              error={loginErrors.password} // Error desde el contexto
              showPasswordToggle
              onTogglePassword={() => setShowPassword(!showPassword)}
              showPassword={showPassword}
              required
            />
          </div>
        </div>

        <div className="flex items-center justify-between">
          <div className="flex items-center">
            <input
              id="remember-me"
              type="checkbox"
              className="h-4 w-4 rounded border-[var(--color-border)] text-[var(--color-primary)] focus:ring-[var(--color-primary)]"
            />
            <label 
              htmlFor="remember-me" 
              className="ml-2 block text-sm text-[var(--color-text-secondary)]"
            >
              Recordarme
            </label>
          </div>
          <button 
            className="text-sm font-medium text-[var(--color-primary)] hover:underline transition-colors"
            type="button"
            onClick={handleForgotPassword}
          >
            ¿Olvidaste tu contraseña?
          </button>
        </div>

        <AuthButton
          onClick={handleSubmit}
          loading={loading}
          disabled={loading || !formData.email.trim() || !formData.password.trim()}
        >
          <span>Iniciar Sesión</span>
          <ArrowRight className="w-5 h-5" />
        </AuthButton>

        <AuthLink
          text="¿No tienes una cuenta?"
          linkText="Regístrate aquí"
          onClick={onSwitchToRegister}
        />
      </div>
    </AuthContainer>
  );
};