import React, { useState, useEffect } from 'react';
import { X, Plus, AlertTriangle, Loader2, Eye, EyeOff, RefreshCw } from 'lucide-react';
import { useUnifiedTheme } from '../../theme/UnifiedThemeProvider';

interface AddPasswordModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSubmit: (passwordData: AddPasswordData) => Promise<{ success: boolean; error?: string }>;
  loading?: boolean;
  prefilledPassword?: string; // Nueva prop para contraseña pre-llenada
}

export interface AddPasswordData {
  website: string;
  username: string;
  password: string;
  algorithm: 'AES' | 'ChaCha20';
}

export const AddPasswordModal: React.FC<AddPasswordModalProps> = ({
  isOpen,
  onClose,
  onSubmit,
  loading = false,
  prefilledPassword = '' // Valor por defecto vacío
}) => {
  const { colors } = useUnifiedTheme();
  const [formData, setFormData] = useState<AddPasswordData>({
    website: '',
    username: '',
    password: '',
    algorithm: 'AES'
  });
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);

  // Reset form when modal opens/closes y pre-llenar contraseña si existe
  useEffect(() => {
    if (!isOpen) {
      setFormData({
        website: '',
        username: '',
        password: '',
        algorithm: 'AES'
      });
      setShowPassword(false);
      setError('');
      setIsSubmitting(false);
    } else if (isOpen && prefilledPassword) {
      // Cuando se abre el modal Y hay una contraseña pre-llenada
      setFormData(prev => ({
        ...prev,
        password: prefilledPassword
      }));
      setShowPassword(true); // Mostrar la contraseña automáticamente
    }
  }, [isOpen, prefilledPassword]);

  const handleInputChange = (field: keyof AddPasswordData, value: string) => {
    setFormData(prev => ({ ...prev, [field]: value }));
    if (error) setError(''); // Clear error when user starts typing
  };

  const generatePassword = () => {
    const length = 16;
    const charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?';
    let password = '';
    
    // Ensure at least one character from each type
    const lowercase = 'abcdefghijklmnopqrstuvwxyz';
    const uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    const numbers = '0123456789';
    const symbols = '!@#$%^&*()_+-=[]{}|;:,.<>?';
    
    password += lowercase[Math.floor(Math.random() * lowercase.length)];
    password += uppercase[Math.floor(Math.random() * uppercase.length)];
    password += numbers[Math.floor(Math.random() * numbers.length)];
    password += symbols[Math.floor(Math.random() * symbols.length)];
    
    // Fill the rest randomly
    for (let i = password.length; i < length; i++) {
      password += charset[Math.floor(Math.random() * charset.length)];
    }
    
    // Shuffle the password
    const shuffled = password.split('').sort(() => Math.random() - 0.5).join('');
    handleInputChange('password', shuffled);
  };

  const validateForm = (): string | null => {
    if (!formData.website.trim()) {
      return 'El sitio web es requerido';
    }
    
    if (!formData.username.trim()) {
      return 'El nombre de usuario es requerido';
    }
    
    if (!formData.password) {
      return 'La contraseña es requerida';
    }
    
    if (formData.password.length < 8) {
      return 'La contraseña debe tener al menos 8 caracteres';
    }
    
    // Validación más flexible para el website - solo verificar que no esté vacío y tenga al menos 3 caracteres
    const websiteValue = formData.website.trim();
    if (websiteValue.length < 3) {
      return 'El sitio web debe tener al menos 3 caracteres';
    }
    
    return null;
  };

  const handleSubmit = async (e?: React.FormEvent) => {
    if (e) {
      e.preventDefault();
    }
    
    const validationError = validateForm();
    if (validationError) {
      setError(validationError);
      return;
    }

    setIsSubmitting(true);
    setError('');

    try {
      // Clean website URL (remove protocol if present)
      const cleanWebsite = formData.website.trim()
        .replace(/^https?:\/\//, '')
        .replace(/^www\./, '');

      const result = await onSubmit({
        ...formData,
        website: cleanWebsite,
        username: formData.username.trim()
      });

      if (result.success) {
        // Reset form and close modal on success
        setFormData({
          website: '',
          username: '',
          password: '',
          algorithm: 'AES'
        });
        setShowPassword(false);
        setError('');
        onClose();
      } else {
        setError(result.error || 'Error al guardar la contraseña');
      }
    } catch (err) {
      setError('Error de conexión. Inténtalo nuevamente.');
      console.error('Error submitting password:', err);
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Escape' && !isSubmitting) {
      onClose();
    }
    if (e.key === 'Enter' && !isSubmitting && !validateForm()) {
      handleSubmit();
    }
  };

  if (!isOpen) return null;

  // El botón estará habilitado si no hay errores de validación y no está enviando
  const isFormValid = !validateForm() && !isSubmitting;

  return (
    <div className="fixed inset-0 flex items-center justify-center p-4 z-50">
      {/* CAMBIO: Fondo con blur y backdrop igual que MasterKeyModal */}
      <div 
        className="absolute inset-0"
        style={{
          backgroundColor: 'rgba(0, 0, 0, 0.4)',
          backdropFilter: 'blur(8px)',
          WebkitBackdropFilter: 'blur(8px)', // Safari support
        }}
        onClick={() => !isSubmitting && onClose()}
      />
      
      {/* Modal content */}
      <div 
        className="relative max-w-md w-full rounded-2xl shadow-2xl border max-h-[90vh] overflow-y-auto"
        onClick={(e) => e.stopPropagation()}
        onKeyDown={handleKeyDown}
        style={{ 
          backgroundColor: colors.surface,
          borderColor: colors.border,
          boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.25)'
        }}
      >
        {/* Header */}
        <div className="flex items-center justify-between p-6 border-b" style={{ borderColor: colors.border }}>
          <div className="flex items-center gap-3">
            <div 
              className="p-2 rounded-lg"
              style={{ backgroundColor: `${colors.primary}20` }}
            >
              <Plus className="w-5 h-5" style={{ color: colors.primary }} />
            </div>
            <h3 className="text-lg font-semibold" style={{ color: colors.textPrimary }}>
              {prefilledPassword ? 'Guardar Contraseña Generada' : 'Agregar Nueva Contraseña'}
            </h3>
          </div>
          {!isSubmitting && (
            <button
              onClick={onClose}
              className="p-1 hover:bg-opacity-80 rounded transition-colors"
              style={{ color: colors.textMuted }}
            >
              <X className="w-5 h-5" />
            </button>
          )}
        </div>

        {/* Form Content */}
        <form onSubmit={handleSubmit} className="p-6 space-y-4">
          {/* Website */}
          <div>
            <label 
              htmlFor="website"
              className="block text-sm font-medium mb-1"
              style={{ color: colors.textPrimary }}
            >
              Sitio Web
            </label>
            <input
              id="website"
              type="text"
              value={formData.website}
              onChange={(e) => handleInputChange('website', e.target.value)}
              placeholder="ejemplo.com"
              className="w-full px-3 py-2 rounded-lg border focus:outline-none focus:ring-2 transition-all duration-200"
              style={{
                backgroundColor: colors.background,
                borderColor: colors.border,
                color: colors.textPrimary
              }}
              disabled={isSubmitting}
              required
            />
          </div>

          {/* Username */}
          <div>
            <label 
              htmlFor="username"
              className="block text-sm font-medium mb-1"
              style={{ color: colors.textPrimary }}
            >
              Usuario/Email
            </label>
            <input
              id="username"
              type="text"
              value={formData.username}
              onChange={(e) => handleInputChange('username', e.target.value)}
              placeholder="usuario@ejemplo.com"
              className="w-full px-3 py-2 rounded-lg border focus:outline-none focus:ring-2 transition-all duration-200"
              style={{
                backgroundColor: colors.background,
                borderColor: colors.border,
                color: colors.textPrimary
              }}
              disabled={isSubmitting}
              required
            />
          </div>

          {/* Password */}
          <div>
            <label 
              htmlFor="password"
              className="block text-sm font-medium mb-1"
              style={{ color: colors.textPrimary }}
            >
              Contraseña
              {prefilledPassword && (
                <span 
                  className="ml-2 text-xs px-2 py-0.5 rounded"
                  style={{ 
                    backgroundColor: `${colors.success}20`,
                    color: colors.success
                  }}
                >
                  Generada automáticamente
                </span>
              )}
            </label>
            <div className="relative">
              <input
                id="password"
                type={showPassword ? 'text' : 'password'}
                value={formData.password}
                onChange={(e) => handleInputChange('password', e.target.value)}
                placeholder="Ingresa una contraseña segura"
                className="w-full px-3 py-2 pr-20 rounded-lg border focus:outline-none focus:ring-2 transition-all duration-200"
                style={{
                  backgroundColor: colors.background,
                  borderColor: colors.border,
                  color: colors.textPrimary
                }}
                disabled={isSubmitting}
                required
              />
              <div className="absolute right-2 top-1/2 transform -translate-y-1/2 flex gap-1">
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="p-1 hover:bg-opacity-80 rounded transition-colors"
                  style={{ color: colors.textMuted }}
                  disabled={isSubmitting}
                >
                  {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
                <button
                  type="button"
                  onClick={generatePassword}
                  className="p-1 hover:bg-opacity-80 rounded transition-colors"
                  style={{ color: colors.primary }}
                  disabled={isSubmitting}
                  title="Generar contraseña"
                >
                  <RefreshCw className="w-4 h-4" />
                </button>
              </div>
            </div>
            {formData.password && formData.password.length < 8 && (
              <p className="text-sm mt-1" style={{ color: colors.warning }}>
                La contraseña debe tener al menos 8 caracteres
              </p>
            )}
          </div>

          {/* Algorithm */}
          <div>
            <label 
              htmlFor="algorithm"
              className="block text-sm font-medium mb-1"
              style={{ color: colors.textPrimary }}
            >
              Algoritmo de Cifrado
            </label>
            <select
              id="algorithm"
              value={formData.algorithm}
              onChange={(e) => handleInputChange('algorithm', e.target.value as 'AES' | 'ChaCha20')}
              className="w-full px-3 py-2 rounded-lg border focus:outline-none focus:ring-2 transition-all duration-200"
              style={{
                backgroundColor: colors.background,
                borderColor: colors.border,
                color: colors.textPrimary
              }}
              disabled={isSubmitting}
            >
              <option value="AES">AES-256 (Recomendado)</option>
              <option value="ChaCha20">ChaCha20</option>
            </select>
          </div>

          {/* Error Message */}
          {error && (
            <div 
              className="flex items-center gap-2 p-3 rounded-lg border"
              style={{ 
                backgroundColor: `${colors.error}20`,
                borderColor: colors.error,
                color: colors.error
              }}
            >
              <AlertTriangle className="w-4 h-4 flex-shrink-0" />
              <span className="text-sm">{error}</span>
            </div>
          )}

          {/* Actions */}
          <div className="flex gap-3 pt-4">
            <button
              type="button"
              onClick={onClose}
              className="flex-1 px-4 py-2 rounded-lg border font-medium hover:bg-opacity-80 transition-colors"
              style={{
                backgroundColor: colors.background,
                borderColor: colors.border,
                color: colors.textSecondary
              }}
              disabled={isSubmitting}
            >
              Cancelar
            </button>
            <button
              type="submit"
              className="flex-1 px-4 py-2 rounded-lg font-medium text-white flex items-center justify-center gap-2 transition-all duration-200 hover:opacity-90"
              style={{ 
                backgroundColor: isFormValid ? colors.primary : colors.textMuted,
                opacity: isFormValid ? 1 : 0.5,
                cursor: isFormValid ? 'pointer' : 'not-allowed'
              }}
              disabled={!isFormValid}
            >
              {isSubmitting ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  Guardando...
                </>
              ) : (
                <>
                  <Plus className="w-4 h-4" />
                  Guardar Contraseña
                </>
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};