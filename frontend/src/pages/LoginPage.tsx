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

    // Validación de email más estricta
    if (!formData.email) {
      newErrors.email = 'El email es requerido';
    } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(formData.email.trim())) {
      newErrors.email = 'El email no es válido';
    }

    // Validación de contraseña
    if (!formData.password) {
      newErrors.password = 'La contraseña es requerida';
    } else if (formData.password.length < 6) {
      newErrors.password = 'La contraseña debe tener al menos 6 caracteres';
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSubmit = async () => {
    // Solo limpiar el apiError, NO los errores de validación
    setApiError('');
    
    if (!validateForm()) return;

    setLoading(true);

    try {
      const result = await login({
        email: formData.email.trim(),
        password: formData.password
      });
      
      if (!result.success) {
        // Manejar diferentes tipos de errores
        const errorMessage = result.error || 'Error en el inicio de sesión';
        
        console.log('Error del backend:', errorMessage); // Para debugging
        
        // Si el error es sobre credenciales, mostrar en campos específicos
        if (errorMessage.toLowerCase().includes('email') || 
            errorMessage.toLowerCase().includes('correo') ||
            errorMessage.toLowerCase().includes('usuario no encontrado')) {
          setErrors(prev => ({ ...prev, email: errorMessage }));
        } else if (errorMessage.toLowerCase().includes('contraseña') || 
                   errorMessage.toLowerCase().includes('password') ||
                   errorMessage.toLowerCase().includes('incorrec')) {
          setErrors(prev => ({ ...prev, password: errorMessage }));
        } else if (errorMessage.toLowerCase().includes('credencial') ||
                   errorMessage.toLowerCase().includes('invalid credentials')) {
          // Error de credenciales genérico - mostrar en ambos campos o como error general
          setApiError('Email o contraseña incorrectos');
        } else {
          // Error general
          setApiError(errorMessage);
        }
      } else {
        // Si es exitoso, limpiar todo
        setErrors({});
        setApiError('');
      }
      // Si es exitoso, el AuthProvider manejará la redirección
    } catch (error) {
      console.error('Login error:', error);
      setApiError('Error de conexión. Verifica tu conexión a internet e inténtalo de nuevo.');
    } finally {
      setLoading(false);
    }
  };

  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      handleSubmit();
    }
  };

  const handleInputChange = (field: keyof FormData) => (value: string) => {
    // Solo limpiar el error específico del campo que se está editando
    if (errors[field]) {
      setErrors(prev => ({ ...prev, [field]: undefined }));
    }
    // Solo limpiar apiError si está relacionado con el campo específico
    if (apiError && field === 'email' && 
        (apiError.toLowerCase().includes('email') || 
         apiError.toLowerCase().includes('correo'))) {
      setApiError('');
    }
    if (apiError && field === 'password' && 
        (apiError.toLowerCase().includes('contraseña') || 
         apiError.toLowerCase().includes('password'))) {
      setApiError('');
    }
    
    setFormData({ ...formData, [field]: value });
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
        {/* Error del API - Más prominente */}
        {apiError && (
          <div className="mb-4">
            <ApiError error={apiError} />
          </div>
        )}

        <InputField
          label="Correo electrónico"
          type="email"
          value={formData.email}
          onChange={handleInputChange('email')}
          placeholder="tu@email.com"
          icon={Mail}
          error={errors.email}
          required
        />

        <InputField
          label="Contraseña"
          type="password"
          value={formData.password}
          onChange={handleInputChange('password')}
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
            onClick={() => setApiError('Función de recuperación de contraseña próximamente disponible')}
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