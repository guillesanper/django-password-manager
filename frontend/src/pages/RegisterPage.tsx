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

    if (!formData.firstName) {
      newErrors.firstName = 'El nombre es requerido';
    } else if (formData.firstName.length < 2) {
      newErrors.firstName = 'El nombre debe tener al menos 2 caracteres';
    }

    if (!formData.lastName) {
      newErrors.lastName = 'El apellido es requerido';
    } else if (formData.lastName.length < 2) {
      newErrors.lastName = 'El apellido debe tener al menos 2 caracteres';
    }

    if (!formData.email) {
      newErrors.email = 'El email es requerido';
    } else if (!/\S+@\S+\.\S+/.test(formData.email)) {
      newErrors.email = 'El email no es válido';
    }

    if (!formData.password) {
      newErrors.password = 'La contraseña es requerida';
    } else if (formData.password.length < 8) {
      newErrors.password = 'La contraseña debe tener al menos 8 caracteres';
    } else if (!/(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/.test(formData.password)) {
      newErrors.password = 'La contraseña debe contener al menos una mayúscula, una minúscula y un número';
    }

    if (!formData.confirmPassword) {
      newErrors.confirmPassword = 'Confirma tu contraseña';
    } else if (formData.password !== formData.confirmPassword) {
      newErrors.confirmPassword = 'Las contraseñas no coinciden';
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSubmit = async () => {
    if (!validateForm()) return;

    setLoading(true);
    setApiError('');

    try {
      const result = await register({
        firstName: formData.firstName || '',
        lastName: formData.lastName || '',
        email: formData.email,
        password: formData.password
      });
      
      if (!result.success) {
        setApiError(result.error || 'Error en el registro');
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

  const getPasswordStrength = (password: string): { strength: number; label: string; color: string } => {
    if (password.length === 0) return { strength: 0, label: '', color: colors.textMuted };
    if (password.length < 6) return { strength: 25, label: 'Débil', color: colors.error };
    if (password.length < 8) return { strength: 50, label: 'Regular', color: colors.warning };
    if (password.length >= 8 && /(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])/.test(password)) {
      return { strength: 100, label: 'Muy Fuerte', color: colors.success };
    }
    if (password.length >= 8 && /(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/.test(password)) {
      return { strength: 85, label: 'Fuerte', color: colors.success };
    }
    return { strength: 65, label: 'Buena', color: colors.primary };
  };

  const passwordStrength = getPasswordStrength(formData.password || '');

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
        {/* Error del API */}
        <ApiError error={apiError} />

        <div className="grid grid-cols-2 gap-4">
          <InputField
            label="Nombre"
            type="text"
            value={formData.firstName || ''}
            onChange={(value) => setFormData({ ...formData, firstName: value })}
            placeholder="Tu nombre"
            icon={User}
            error={errors.firstName}
            required
          />

          <InputField
            label="Apellido"
            type="text"
            value={formData.lastName || ''}
            onChange={(value) => setFormData({ ...formData, lastName: value })}
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
          onChange={(value) => setFormData({ ...formData, email: value })}
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
            onChange={(value) => setFormData({ ...formData, password: value })}
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
                <p className={`transition-colors ${formData.password.length >= 8 ? 'text-[var(--color-success)]' : 'text-[var(--color-text-muted)]'}`}>
                  ✓ Al menos 8 caracteres
                </p>
                <p className={`transition-colors ${/(?=.*[a-z])(?=.*[A-Z])/.test(formData.password) ? 'text-[var(--color-success)]' : 'text-[var(--color-text-muted)]'}`}>
                  ✓ Mayúsculas y minúsculas
                </p>
                <p className={`transition-colors ${/(?=.*\d)/.test(formData.password) ? 'text-[var(--color-success)]' : 'text-[var(--color-text-muted)]'}`}>
                  ✓ Al menos un número
                </p>
              </div>
            </div>
          )}
        </div>

        <InputField
          label="Confirmar contraseña"
          type="password"
          value={formData.confirmPassword || ''}
          onChange={(value) => setFormData({ ...formData, confirmPassword: value })}
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
          disabled={loading}
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