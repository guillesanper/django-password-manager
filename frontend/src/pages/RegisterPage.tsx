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
import { useRegisterErrorHandler } from '../components/hooks/AuthErrorProvider'; // NUEVA IMPORTACIÓN

export interface RegisterPageProps {
  onSwitchToLogin: () => void;
}

export const RegisterPage: React.FC<RegisterPageProps> = ({ 
  onSwitchToLogin
}) => {
  const { colors } = useUnifiedTheme();
  const { register } = useAuth();
  
  // Usar el hook de errores de registro
  const { 
    registerErrors, 
    registerApiError, 
    clearRegisterErrors, 
    classifyAndSetError,
    handleFieldChange,
    validateForm,
    setRegisterErrors
  } = useRegisterErrorHandler();
  
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

  const handleSubmit = async () => {
    // Limpiar solo el apiError al inicio, no los errores de campo
    clearRegisterErrors();

    // Validar formulario usando el hook
    const { isValid, errors } = validateForm(formData);
    
    if (!isValid) {
      setRegisterErrors(errors);
      return;
    }

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
        
        // Usar el clasificador de errores del contexto
        classifyAndSetError(errorMessage);
      } else {
        // Si es exitoso, limpiar todo
        clearRegisterErrors();
      }
    } catch (error) {
      console.error('Register error:', error);
      classifyAndSetError('Error de conexión. Verifica tu conexión a internet e inténtalo de nuevo.');
    } finally {
      setLoading(false);
    }
  };

  const handleKeyPress = (e: React.KeyboardEvent) => {
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

  const getPasswordStrength = (password: string): { strength: number; label: string; color: string } => {
    if (password.length === 0) return { strength: 0, label: '', color: colors?.textMuted || '#6B7280' };
    if (password.length < 6) return { strength: 25, label: 'Débil', color: colors?.error || '#EF4444' };
    if (password.length < 12) return { strength: 50, label: 'Regular', color: colors?.warning || '#F59E0B' };
    
    // Verificar complejidad para contraseñas de 12+ caracteres
    const hasLower = /(?=.*[a-z])/.test(password);
    const hasUpper = /(?=.*[A-Z])/.test(password);
    const hasNumber = /(?=.*\d)/.test(password);
    const hasSymbol = /(?=.*[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?`~])/.test(password);
    
    const complexityScore = [hasLower, hasUpper, hasNumber, hasSymbol].filter(Boolean).length;
    
    if (password.length >= 12 && complexityScore === 4) {
      return { strength: 100, label: 'Muy Fuerte', color: colors?.success || '#10B981' };
    }
    if (password.length >= 12 && complexityScore >= 3) {
      return { strength: 85, label: 'Fuerte', color: colors?.success || '#10B981' };
    }
    if (password.length >= 8 && complexityScore >= 2) {
      return { strength: 65, label: 'Buena', color: colors?.primary || '#6366F1' };
    }
    
    return { strength: 40, label: 'Mejorable', color: colors?.warning || '#F59E0B' };
  };

  const passwordStrength = getPasswordStrength(formData.password || '');

  // Verificar si el formulario es válido para habilitar el botón
  const isFormValid = () => {
    return formData.firstName?.trim() && 
           formData.lastName?.trim() && 
           formData.email?.trim() && 
           formData.password && 
           formData.confirmPassword &&
           formData.password === formData.confirmPassword;
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
        {/* Error del API - Ahora desde el contexto */}
        {registerApiError && (
          <div className="mb-4">
            <ApiError error={registerApiError} />
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
            error={registerErrors.firstName} // Error desde el contexto
            required
          />

          <InputField
            label="Apellido"
            type="text"
            value={formData.lastName || ''}
            onChange={handleInputChange('lastName')}
            placeholder="Tu apellido"
            icon={User}
            error={registerErrors.lastName} // Error desde el contexto
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
          error={registerErrors.email} // Error desde el contexto
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
            error={registerErrors.password} // Error desde el contexto
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
                <p className={`transition-colors flex items-center gap-1 ${formData.password.length >= 12 ? 'text-[var(--color-success)]' : 'text-[var(--color-text-muted)]'}`}>
                  <span>{formData.password.length >= 12 ? '✓' : '○'}</span> Al menos 12 caracteres
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
          error={registerErrors.confirmPassword} // Error desde el contexto
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