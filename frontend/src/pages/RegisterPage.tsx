import React, { useState } from 'react';
import { User, Mail, Lock, ArrowRight, Key, CheckCircle } from 'lucide-react';
import { 
  InputField, 
  AuthButton, 
  AuthContainer, 
  ApiError, 
  InfoBox,
  AuthLink,
} from '../components/AuthComponents';
import type { FormData } from '../components/AuthComponents';
import { useUnifiedTheme } from '../theme/UnifiedThemeProvider';
import { useAuth } from '../components/AuthProvider';

export interface RegisterPageProps {
  onSwitchToLogin: () => void;
}

export const RegisterPage: React.FC<RegisterPageProps> = ({ 
  onSwitchToLogin
}) => {
  const { colors } = useUnifiedTheme();
  const { register } = useAuth();
  
  const [formData, setFormData] = useState<FormData>({
    firstName: '',
    lastName: '',
    email: '',
    password: '',
    confirmPassword: ''
  });
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [errors, setErrors] = useState<Partial<FormData>>({});
  const [apiError, setApiError] = useState<string>('');

  const validateForm = (): boolean => {
    const newErrors: Partial<FormData> = {};

    // Validación de nombre
    if (!formData.firstName?.trim()) {
      newErrors.firstName = 'El nombre es requerido';
    } else if (formData.firstName.trim().length < 2) {
      newErrors.firstName = 'El nombre debe tener al menos 2 caracteres';
    } else if (!/^[a-zA-ZÀ-ÿ\s]+$/.test(formData.firstName.trim())) {
      newErrors.firstName = 'El nombre solo puede contener letras';
    }

    // Validación de apellido
    if (!formData.lastName?.trim()) {
      newErrors.lastName = 'El apellido es requerido';
    } else if (formData.lastName.trim().length < 2) {
      newErrors.lastName = 'El apellido debe tener al menos 2 caracteres';
    } else if (!/^[a-zA-ZÀ-ÿ\s]+$/.test(formData.lastName.trim())) {
      newErrors.lastName = 'El apellido solo puede contener letras';
    }

    // Validación de email más estricta
    if (!formData.email?.trim()) {
      newErrors.email = 'El email es requerido';
    } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(formData.email.trim())) {
      newErrors.email = 'El email no es válido';
    }

    // Validación de contraseña más robusta
    if (!formData.password) {
      newErrors.password = 'La contraseña es requerida';
    } else if (formData.password.length < 12) {
      newErrors.password = 'La contraseña debe tener al menos 12 caracteres';
    } else if (!/(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/.test(formData.password)) {
      newErrors.password = 'La contraseña debe contener al menos una mayúscula, una minúscula, un número y un símbolo';
    }

    // Validación de confirmación de contraseña
    if (!formData.confirmPassword) {
      newErrors.confirmPassword = 'Confirma tu contraseña';
    } else if (formData.password !== formData.confirmPassword) {
      newErrors.confirmPassword = 'Las contraseñas no coinciden';
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSubmit = async () => {
    // NO limpiar errores previos inmediatamente, solo el apiError
    setApiError('');

    if (!validateForm()) return;

    setLoading(true);

    try {
      const result = await register({
        firstName: formData.firstName?.trim() || '',
        lastName: formData.lastName?.trim() || '',
        email: formData.email.trim(),
        password: formData.password
      });
      
      if (!result.success) {
        const errorMessage = result.error || 'Error en el registro';
        
        console.log('Error del backend:', errorMessage); // Para debugging
        
        // Manejar errores específicos del backend
        if (errorMessage.toLowerCase().includes('email') || 
            errorMessage.toLowerCase().includes('correo') ||
            errorMessage.toLowerCase().includes('existe') ||
            errorMessage.toLowerCase().includes('already') ||
            errorMessage.toLowerCase().includes('ya registrado')) {
          setErrors(prev => ({ ...prev, email: errorMessage }));
        } else if (errorMessage.toLowerCase().includes('contraseña') || 
                   errorMessage.toLowerCase().includes('password')) {
          setErrors(prev => ({ ...prev, password: errorMessage }));
        } else if (errorMessage.toLowerCase().includes('nombre') ||
                   errorMessage.toLowerCase().includes('first_name')) {
          setErrors(prev => ({ ...prev, firstName: errorMessage }));
        } else if (errorMessage.toLowerCase().includes('apellido') ||
                   errorMessage.toLowerCase().includes('last_name')) {
          setErrors(prev => ({ ...prev, lastName: errorMessage }));
        } else {
          // Error general - mostrar en ApiError
          setApiError(errorMessage);
        }
      } else {
        // Si es exitoso, limpiar todo
        setErrors({});
        setApiError('');
      }
    } catch (error) {
      console.error('Register error:', error);
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
    // Solo limpiar apiError si es un error general
    if (apiError && field === 'email' && 
        (apiError.toLowerCase().includes('email') || 
         apiError.toLowerCase().includes('correo'))) {
      setApiError('');
    }
    
    setFormData({ ...formData, [field]: value });
  };

  const getPasswordStrength = (password: string): { strength: number; label: string; color: string } => {
    if (password.length === 0) return { strength: 0, label: '', color: colors?.textMuted || '#6B7280' };
    if (password.length < 6) return { strength: 25, label: 'Débil', color: colors?.error || '#EF4444' };
    if (password.length < 8) return { strength: 50, label: 'Regular', color: colors?.warning || '#F59E0B' };
    if (password.length >= 8 && /(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])/.test(password)) {
      return { strength: 100, label: 'Muy Fuerte', color: colors?.success || '#10B981' };
    }
    if (password.length >= 8 && /(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/.test(password)) {
      return { strength: 85, label: 'Fuerte', color: colors?.success || '#10B981' };
    }
    return { strength: 65, label: 'Buena', color: colors?.primary || '#6366F1' };
  };

  const passwordStrength = getPasswordStrength(formData.password || '');

  // Verificar si el formulario es válido para habilitar el botón
  const isFormValid = () => {
    return formData.firstName?.trim() && 
           formData.lastName?.trim() && 
           formData.email?.trim() && 
           formData.password && 
           formData.confirmPassword;
  };

  return (
    <AuthContainer
      title="Crear Cuenta"
      subtitle="Únete a PasswordManager y protege tus credenciales"
      icon={
        <div className="p-3 rounded-full bg-gradient-to-r from-emerald-500 to-teal-600">
          <Key className="w-8 h-8 text-white" />
        </div>
      }
    >
      <div className="space-y-6" onKeyPress={handleKeyPress}>
        {/* Error del API - Siempre visible si existe */}
        {apiError && (
          <div className="mb-4">
            <ApiError error={apiError} />
          </div>
        )}

        <div className="grid grid-cols-2 gap-4">
          <InputField
            label="Nombre"
            type="text"
            value={formData.firstName || ''}
            onChange={handleInputChange('firstName')}
            placeholder="Tu nombre"
            icon={User}
            error={errors.firstName}
            required
          />

          <InputField
            label="Apellido"
            type="text"
            value={formData.lastName || ''}
            onChange={handleInputChange('lastName')}
            placeholder="Tu apellido"
            icon={User}
            error={errors.lastName}
            required
          />
        </div>

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

        <div>
          <InputField
            label="Contraseña"
            type="password"
            value={formData.password}
            onChange={handleInputChange('password')}
            placeholder="Crea una contraseña segura"
            icon={Lock}
            error={errors.password}
            showPasswordToggle
            onTogglePassword={() => setShowPassword(!showPassword)}
            showPassword={showPassword}
            required
          />
          
          {formData.password && (
            <div className="mt-2 space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs text-[var(--color-text-muted)]">
                  Seguridad de la contraseña
                </span>
                <span 
                  className="text-xs font-medium" 
                  style={{ color: passwordStrength.color }}
                >
                  {passwordStrength.label}
                </span>
              </div>
              <div className="w-full bg-[var(--color-border)] rounded-full h-1.5">
                <div
                  className="h-1.5 rounded-full transition-all duration-300"
                  style={{
                    width: `${passwordStrength.strength}%`,
                    backgroundColor: passwordStrength.color
                  }}
                ></div>
              </div>
              {/* Requerimientos de contraseña */}
              <div className="text-xs space-y-1">
                <p className={`transition-colors flex items-center gap-1 ${formData.password.length >= 8 ? 'text-[var(--color-success)]' : 'text-[var(--color-text-muted)]'}`}>
                  <span>{formData.password.length >= 8 ? '✓' : '○'}</span> Al menos 12 caracteres
                </p>
                <p className={`transition-colors flex items-center gap-1 ${/(?=.*[a-z])(?=.*[A-Z])/.test(formData.password) ? 'text-[var(--color-success)]' : 'text-[var(--color-text-muted)]'}`}>
                  <span>{/(?=.*[a-z])(?=.*[A-Z])/.test(formData.password) ? '✓' : '○'}</span> Mayúsculas y minúsculas
                </p>
                <p className={`transition-colors flex items-center gap-1 ${/(?=.*\d)/.test(formData.password) ? 'text-[var(--color-success)]' : 'text-[var(--color-text-muted)]'}`}>
                  <span>{/(?=.*\d)/.test(formData.password) ? '✓' : '○'}</span> Al menos un número
                </p>
                <p className={`transition-colors flex items-center gap-1 ${/(?=.*[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?`~])/.test(formData.password) ? 'text-[var(--color-success)]' : 'text-[var(--color-text-muted)]'}`}>
                  <span>{/(?=.*[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?`~])/.test(formData.password) ? '✓' : '○'}</span> Al menos un símbolo
                </p>
              </div>
            </div>
          )}
        </div>

        <InputField
          label="Confirmar contraseña"
          type="password"
          value={formData.confirmPassword || ''}
          onChange={handleInputChange('confirmPassword')}
          placeholder="Confirma tu contraseña"
          icon={Lock}
          error={errors.confirmPassword}
          showPasswordToggle
          onTogglePassword={() => setShowConfirmPassword(!showConfirmPassword)}
          showPassword={showConfirmPassword}
          required
        />

        <InfoBox icon={<CheckCircle className="w-5 h-5" />}>
          <p className="font-medium mb-1">Tu cuenta incluye:</p>
          <ul className="space-y-1 text-xs">
            <li>• Almacenamiento ilimitado de contraseñas</li>
            <li>• Generador de contraseñas seguras</li>
            <li>• Encriptación de archivos</li>
            <li>• Sincronización en todos tus dispositivos</li>
          </ul>
        </InfoBox>

        <AuthButton
          onClick={handleSubmit}
          loading={loading}
          disabled={loading || !isFormValid()}
        >
          <span>Crear Cuenta</span>
          <ArrowRight className="w-5 h-5" />
        </AuthButton>

        <AuthLink
          text="¿Ya tienes una cuenta?"
          linkText="Inicia sesión aquí"
          onClick={onSwitchToLogin}
        />
      </div>
    </AuthContainer>
  );
};