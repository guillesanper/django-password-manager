import React, { useState, useEffect } from 'react';
import { X, Edit2, AlertTriangle, Loader2, Eye, EyeOff, RefreshCw, Shield, CheckCircle } from 'lucide-react';
import { useUnifiedTheme } from '../UnifiedThemeProvider';
import { type PasswordAccount } from './AccountCard';
import { generateStrongPassword } from '../../services/passwordGenerator';

export interface EditPasswordData {
  website: string;
  username: string;
  password?: string; // Opcional porque puede que no quieran cambiar la contraseña
  algorithm: 'AES' | 'ChaCha20';
}

interface EditPasswordModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSubmit: (accountId: number, passwordData: EditPasswordData, masterPassword?: string) => Promise<{ success: boolean; error?: string; message?: string }>;
  onRequestMasterPassword: (accountId: number, formData: EditPasswordData) => void; // Nueva prop
  account: PasswordAccount | null;
  loading?: boolean;
  masterPasswordValidated?: boolean; // Nueva prop para saber si ya se validó la master password
}

export const EditPasswordModal: React.FC<EditPasswordModalProps> = ({
  isOpen,
  onClose,
  onSubmit,
  onRequestMasterPassword, // Nueva prop
  account,
  masterPasswordValidated = false // Nueva prop
}) => {
  const { colors } = useUnifiedTheme();
  const [formData, setFormData] = useState<EditPasswordData>({
    website: '',
    username: '',
    password: '',
    algorithm: 'AES'
  });
  const [showPassword, setShowPassword] = useState(false);
  const [changePassword, setChangePassword] = useState(false);
  const [error, setError] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [successMessage, setSuccessMessage] = useState('');

  // Reset form when modal opens/closes or account changes
  useEffect(() => {
    if (!isOpen || !account) {
      setFormData({
        website: '',
        username: '',
        password: '',
        algorithm: 'AES'
      });
      setShowPassword(false);
      setChangePassword(false);
      setError('');
      setSuccessMessage('');
      setIsSubmitting(false);
    } else if (isOpen && account) {
      // Pre-llenar con los datos actuales de la cuenta
      setFormData({
        website: account.website,
        username: account.username,
        password: '',
        algorithm: (account.encryption_algorithm === 'ChaCha20' ? 'ChaCha20' : 'AES') as 'AES' | 'ChaCha20'
      });
      
      // Si ya se validó la master password, marcar el checkbox de cambiar contraseña
      setChangePassword(masterPasswordValidated);
      setShowPassword(false);
      setError('');
      setSuccessMessage('');
      setIsSubmitting(false);
    }
  }, [isOpen, account, masterPasswordValidated]);

  const handleInputChange = (field: keyof EditPasswordData, value: string) => {
    setFormData(prev => ({ ...prev, [field]: value }));
    if (error) setError(''); // Clear error when user starts typing
    if (successMessage) setSuccessMessage(''); // Clear success message
  };

  const handleChangePasswordToggle = (checked: boolean) => {
    if (checked && !masterPasswordValidated) {
      // Si quiere cambiar contraseña pero no se ha validado la master password
      // Solicitar validación de master password
      onRequestMasterPassword(account?.id || 0, formData);
      return;
    }
    
    // Si ya está validado o está desmarcando, proceder normalmente
    setChangePassword(checked);
    if (!checked) {
      handleInputChange('password', '');
      setShowPassword(false);
    }
  };

  const generatePassword = () => {
    handleInputChange('password', generateStrongPassword(16));
    setShowPassword(true);
  };

  const validateForm = (): string | null => {
    if (!formData.website.trim()) {
      return 'El sitio web es requerido';
    }
    
    if (!formData.username.trim()) {
      return 'El nombre de usuario es requerido';
    }
    
    // Si decidieron cambiar la contraseña, validarla
    if (changePassword) {
      if (!formData.password) {
        return 'La contraseña es requerida';
      }
      
      if (formData.password.length < 8) {
        return 'La contraseña debe tener al menos 8 caracteres';
      }
    }
    
    // Validación del website
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
    
    if (!account) {
      setError('No se encontró la cuenta a editar');
      return;
    }
    
    const validationError = validateForm();
    if (validationError) {
      setError(validationError);
      return;
    }

    setIsSubmitting(true);
    setError('');
    setSuccessMessage('');

    try {
      // Clean website URL (remove protocol if present)
      const cleanWebsite = formData.website.trim()
        .replace(/^https?:\/\//, '')
        .replace(/^www\./, '');

      const updateData: EditPasswordData = {
        website: cleanWebsite,
        username: formData.username.trim(),
        algorithm: formData.algorithm
      };

      // Solo incluir la contraseña si decidieron cambiarla
      if (changePassword && formData.password) {
        updateData.password = formData.password;
      }

      const result = await onSubmit(account.id, updateData);

      if (result.success) {
        setSuccessMessage(result.message || 'Contraseña actualizada exitosamente');
        
        // Auto cerrar el modal después de un breve delay
        setTimeout(() => {
          // Reset form and close modal on success
          setFormData({
            website: '',
            username: '',
            password: '',
            algorithm: 'AES'
          });
          setShowPassword(false);
          setChangePassword(false);
          setError('');
          setSuccessMessage('');
          onClose();
        }, 1500);
      } else {
        setError(result.error || 'Error al actualizar la contraseña');
      }
    } catch (err) {
      setError('Error de conexión. Inténtalo nuevamente.');
      console.error('Error updating password:', err);
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Escape' && !isSubmitting && !successMessage) {
      onClose();
    }
    if (e.key === 'Enter' && !isSubmitting && !validateForm() && !successMessage) {
      handleSubmit();
    }
  };

  const getFaviconUrl = (website: string) => {
    const domain = website.replace(/^https?:\/\//, '').replace(/^www\./, '');
    return `https://www.google.com/s2/favicons?domain=${domain}&sz=32`;
  };

  if (!isOpen || !account) return null;

  // El botón estará habilitado si no hay errores de validación y no está enviando
  const isFormValid = !validateForm() && !isSubmitting && !successMessage;

  return (
    <div className="fixed inset-0 flex items-center justify-center p-4 z-50">
      {/* Fondo con blur y backdrop */}
      <div 
        className="absolute inset-0"
        style={{
          backgroundColor: 'rgba(0, 0, 0, 0.4)',
          backdropFilter: 'blur(8px)',
          WebkitBackdropFilter: 'blur(8px)', // Safari support
        }}
        onClick={() => !isSubmitting && !successMessage && onClose()}
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
            <div className="flex items-center gap-3">
              <div 
                className="p-2 rounded-lg"
                style={{ 
                  backgroundColor: successMessage ? `${colors.success}20` : `${colors.warning}20`
                }}
              >
                {successMessage ? (
                  <CheckCircle className="w-5 h-5" style={{ color: colors.success }} />
                ) : (
                  <Edit2 className="w-5 h-5" style={{ color: colors.warning }} />
                )}
              </div>
              <div>
                <h3 className="text-lg font-semibold" style={{ color: colors.textPrimary }}>
                  {successMessage ? 'Contraseña Actualizada' : 'Editar Contraseña'}
                </h3>
                <div className="flex items-center gap-2 mt-1">
                  <img
                    src={getFaviconUrl(account.website)}
                    alt={account.website}
                    className="w-4 h-4"
                    onError={(e) => {
                      (e.target as HTMLImageElement).src = 'data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="m9 12 2 2 4-4"/></svg>';
                    }}
                  />
                  <span 
                    className="text-sm"
                    style={{ color: colors.textSecondary }}
                  >
                    {account.website}
                  </span>
                </div>
              </div>
            </div>
          </div>
          {!isSubmitting && !successMessage && (
            <button
              onClick={onClose}
              className="p-1 hover:bg-opacity-80 rounded transition-colors"
              style={{ color: colors.textMuted }}
            >
              <X className="w-5 h-5" />
            </button>
          )}
        </div>

        {/* Success Message */}
        {successMessage && (
          <div className="p-6">
            <div 
              className="flex items-center gap-2 p-4 rounded-lg border"
              style={{ 
                backgroundColor: `${colors.success}20`,
                borderColor: colors.success,
                color: colors.success
              }}
            >
              <CheckCircle className="w-5 h-5 flex-shrink-0" />
              <span className="text-sm font-medium">{successMessage}</span>
            </div>
          </div>
        )}

        {/* Form Content - Solo mostrar si no hay mensaje de éxito */}
        {!successMessage && (
          <form onSubmit={handleSubmit} className="p-6 space-y-4">
            {/* Website */}
            <div>
              <label 
                htmlFor="edit-website"
                className="block text-sm font-medium mb-1"
                style={{ color: colors.textPrimary }}
              >
                Sitio Web
              </label>
              <input
                id="edit-website"
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
                htmlFor="edit-username"
                className="block text-sm font-medium mb-1"
                style={{ color: colors.textPrimary }}
              >
                Usuario/Email
              </label>
              <input
                id="edit-username"
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

            {/* Password Change Toggle */}
            <div className="border rounded-lg p-4" style={{ borderColor: colors.border }}>
              <div className="flex items-center gap-3 mb-3">
                <div className="flex items-center">
                  <input
                    id="change-password-checkbox"
                    type="checkbox"
                    checked={changePassword}
                    onChange={(e) => handleChangePasswordToggle(e.target.checked)}
                    className="w-4 h-4 rounded border focus:ring-2"
                    style={{ 
                      accentColor: colors.primary,
                      borderColor: colors.border
                    }}
                    disabled={isSubmitting}
                  />
                  <label 
                    htmlFor="change-password-checkbox"
                    className="ml-2 text-sm font-medium cursor-pointer"
                    style={{ color: colors.textPrimary }}
                  >
                    Cambiar contraseña
                  </label>
                </div>
                {masterPasswordValidated && changePassword && (
                  <div 
                    className="flex items-center gap-1 px-2 py-1 rounded"
                    style={{ 
                      backgroundColor: `${colors.success}20`,
                      color: colors.success
                    }}
                  >
                    <Shield className="w-3 h-3" />
                    <span className="text-xs">Autorizado</span>
                  </div>
                )}
              </div>
              
              {!changePassword && (
                <p className="text-sm" style={{ color: colors.textSecondary }}>
                  La contraseña actual se mantendrá sin cambios
                </p>
              )}
            </div>

            {/* Password Field - Only show if changing */}
            {changePassword && (
              <div>
                <label 
                  htmlFor="edit-password"
                  className="block text-sm font-medium mb-1"
                  style={{ color: colors.textPrimary }}
                >
                  Nueva Contraseña
                </label>
                <div className="relative">
                  <input
                    id="edit-password"
                    type={showPassword ? 'text' : 'password'}
                    value={formData.password}
                    onChange={(e) => handleInputChange('password', e.target.value)}
                    placeholder="Ingresa la nueva contraseña"
                    className="w-full px-3 py-2 pr-20 rounded-lg border focus:outline-none focus:ring-2 transition-all duration-200"
                    style={{
                      backgroundColor: colors.background,
                      borderColor: colors.border,
                      color: colors.textPrimary
                    }}
                    disabled={isSubmitting}
                    required={changePassword}
                  />
                  <div className="absolute right-2 top-1/2 transform -translate-y-1/2 flex gap-1">
                    <button
                      type="button"
                      onClick={() => setShowPassword(!showPassword)}
                      className="p-1 hover:bg-opacity-80 rounded transition-colors"
                      style={{ color: colors.textMuted }}
                      disabled={isSubmitting}
                      title={showPassword ? 'Ocultar contraseña' : 'Mostrar contraseña'}
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
                {changePassword && formData.password && formData.password.length < 8 && (
                  <p className="text-sm mt-1" style={{ color: colors.warning }}>
                    La contraseña debe tener al menos 8 caracteres
                  </p>
                )}
              </div>
            )}

            {/* Algorithm */}
            <div>
              <label 
                htmlFor="edit-algorithm"
                className="block text-sm font-medium mb-1"
                style={{ color: colors.textPrimary }}
              >
                Algoritmo de Cifrado
              </label>
              <select
                id="edit-algorithm"
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
                  backgroundColor: isFormValid ? colors.warning : colors.textMuted,
                  opacity: isFormValid ? 1 : 0.5,
                  cursor: isFormValid ? 'pointer' : 'not-allowed'
                }}
                disabled={!isFormValid}
              >
                {isSubmitting ? (
                  <>
                    <Loader2 className="w-4 h-4 animate-spin" />
                    Actualizando...
                  </>
                ) : (
                  <>
                    <Edit2 className="w-4 h-4" />
                    Actualizar Contraseña
                  </>
                )}
              </button>
            </div>
          </form>
        )}
      </div>
    </div>
  );
};