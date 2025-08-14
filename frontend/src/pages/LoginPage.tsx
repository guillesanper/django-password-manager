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

export interface LoginPageProps {
  onSwitchToRegister: () => void;
}

export const LoginPage: React.FC<LoginPageProps> = ({ 
  onSwitchToRegister
}) => {
  const { login } = useAuth();
  
  const [formData, setFormData] = useState<FormData>({
    email: '',
    password: ''
  });
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [errors, setErrors] = useState<Partial<FormData>>({});
  const [apiError, setApiError] = useState<string>('');

  const validateForm = (): boolean => {
    const newErrors: Partial<FormData> = {};

    if (!formData.email) {
      newErrors.email = 'El email es requerido';
    } else if (!/\S+@\S+\.\S+/.test(formData.email)) {
      newErrors.email = 'El email no es válido';
    }

    if (!formData.password) {
      newErrors.password = 'La contraseña es requerida';
    } else if (formData.password.length < 6) {
      newErrors.password = 'La contraseña debe tener al menos 6 caracteres';
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSubmit = async () => {
    if (!validateForm()) return;

    setLoading(true);
    setApiError('');

    try {
      const result = await login({
        email: formData.email,
        password: formData.password
      });
      
      if (!result.success) {
        setApiError(result.error || 'Error en el inicio de sesión');
      }
      // Si es exitoso, el AuthProvider manejará la redirección
    } catch (error) {
      setApiError('Error de conexión. Inténtalo de nuevo.');
    } finally {
      setLoading(false);
    }
  };

  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') {
      handleSubmit();
    }
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
      <div className="space-y-6" onKeyPress={handleKeyPress}>
        {/* Error del API */}
        <ApiError error={apiError} />

        <InputField
          label="Correo electrónico"
          type="email"
          value={formData.email}
          onChange={(value) => setFormData({ ...formData, email: value })}
          placeholder="tu@email.com"
          icon={Mail}
          error={errors.email}
          required
        />

        <InputField
          label="Contraseña"
          type="password"
          value={formData.password}
          onChange={(value) => setFormData({ ...formData, password: value })}
          placeholder="Tu contraseña"
          icon={Lock}
          error={errors.password}
          showPasswordToggle
          onTogglePassword={() => setShowPassword(!showPassword)}
          showPassword={showPassword}
          required
        />

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
          >
            ¿Olvidaste tu contraseña?
          </button>
        </div>

        <AuthButton
          onClick={handleSubmit}
          loading={loading}
          disabled={loading}
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