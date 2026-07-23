import React, { useState, useEffect, useRef } from 'react';
import { X, Plus, AlertTriangle, Loader2, Eye, EyeOff, RefreshCw, CheckCircle, ChevronDown, ChevronUp, Lock, Folder } from 'lucide-react';
import { useUnifiedTheme } from '../UnifiedThemeProvider';
import { useVaults } from '../hooks/useVaults';
import { UnlockVaultModal } from '../vaults/UnlockVaultModal';
import { VAULT_COLORS, type Vault, vaultService } from '../../services/vaultService';

interface AddPasswordModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSubmit: (passwordData: AddPasswordWithVaultData) => Promise<{ success: boolean; error?: string; message?: string }>;
  loading?: boolean;
  preselectedVault?: Vault | null;
  prefilledPassword?: string;
}

export interface AddPasswordData {
  website: string;
  username: string;
  password: string;
  algorithm: 'AES' | 'ChaCha20';
}

export interface AddPasswordWithVaultData extends AddPasswordData {
  vault_id?: number | null;
  vault_password?: string;
  vault_already_unlocked?: boolean;
}

export const AddPasswordModal: React.FC<AddPasswordModalProps> = ({
  isOpen,
  onClose,
  onSubmit,  
  preselectedVault = null, 
  prefilledPassword = ''
}) => {
  const { colors } = useUnifiedTheme();
  const { vaults, loading: vaultsLoading, isVaultUnlocked, markVaultAsUnlocked } = useVaults();  
  const dropdownRef = useRef<HTMLDivElement>(null);
  
  const [formData, setFormData] = useState<AddPasswordData>({
    website: '',
    username: '',
    password: '',
    algorithm: 'AES'
  });
  
  // Estados para vault functionality - SIMPLIFICADO (removido includeInVault)
  const [selectedVaultId, setSelectedVaultId] = useState<number | null>(null);
  const [vaultPassword, setVaultPassword] = useState('');
  const [showUnlockVault, setShowUnlockVault] = useState(false);
  const [vaultToUnlock, setVaultToUnlock] = useState<Vault | null>(null);
  const [, setVaultUnlockError] = useState('');
  const [isUnlockingVault, setIsUnlockingVault] = useState(false);

  // Estados del combobox
  const [isVaultDropdownOpen, setIsVaultDropdownOpen] = useState(false);
  
  // Estados del formulario
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [successMessage, setSuccessMessage] = useState('');

  // Cerrar dropdown al hacer click fuera
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setIsVaultDropdownOpen(false);
      }
    };

    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  // Reset form when modal opens/closes y pre-llenar contraseña si existe
  // En AddPasswordModal.tsx - Reemplaza el useEffect problemático

useEffect(() => {
  if (!isOpen) {
    setFormData({
      website: '',
      username: '',
      password: '',
      algorithm: 'AES'
    });
    setSelectedVaultId(null);
    setVaultPassword('');
    setIsVaultDropdownOpen(false);
    setShowPassword(false);
    setError('');
    setSuccessMessage('');
    setIsSubmitting(false);
    setVaultUnlockError('');
  } else if (isOpen) {
    // Pre-llenar contraseña si existe
    if (prefilledPassword) {
      setFormData(prev => ({
        ...prev,
        password: prefilledPassword
      }));
      setShowPassword(true);
    }

    // NUEVO: Manejar vault preseleccionado - CON VALIDACIÓN MEJORADA
    if (preselectedVault) {
      console.log('Preselected vault:', preselectedVault);
      console.log('Is vault unlocked?', isVaultUnlocked(preselectedVault.id));
      
      setSelectedVaultId(preselectedVault.id);
      
      // Solo mostrar unlock si es privado Y no está desbloqueado
      if (preselectedVault.is_private) {
        const isUnlocked = isVaultUnlocked(preselectedVault.id);
        console.log('Vault is private. Unlocked status:', isUnlocked);
        
        if (!isUnlocked) {
          console.log('Showing unlock modal for vault:', preselectedVault.name);
          setVaultToUnlock(preselectedVault);
          setShowUnlockVault(true);
        } else {
          console.log('Vault already unlocked, no need to show unlock modal');
          // Vault ya está desbloqueado, no mostrar modal
          setVaultToUnlock(null);
          setShowUnlockVault(false);
        }
      } else {
        console.log('Vault is public, no unlock needed');
        // Vault público, no necesita desbloqueo
        setVaultToUnlock(null);
        setShowUnlockVault(false);
      }
    }

    setError('');
    setSuccessMessage('');
    setVaultUnlockError('');
  }
}, [isOpen, prefilledPassword, preselectedVault, isVaultUnlocked]);

  const handleInputChange = (field: keyof AddPasswordData, value: string) => {
    setFormData(prev => ({ ...prev, [field]: value }));
    if (error) setError('');
    if (successMessage) setSuccessMessage('');
  };

  const handleVaultSelect = (vault: Vault | null) => {
    setIsVaultDropdownOpen(false);
    
    if (!vault) {
      // Sin vault seleccionado
      setSelectedVaultId(null);
      setVaultPassword('');
      return;
    }
    
    if (vault.is_private && !isVaultUnlocked(vault.id)) {
      // Si es privado y no está desbloqueado, mostrar modal de unlock
      setVaultToUnlock(vault);
      setShowUnlockVault(true);
    } else {
      // Si es público o ya está desbloqueado, seleccionar directamente
      setSelectedVaultId(vault.id);
      setVaultPassword(''); // Limpiar password si cambia de vault
    }
  };

  const handleUnlockVault = async (password: string) => {
    if (!vaultToUnlock) return { success: false, message: 'No hay vault para desbloquear' };
    
    setIsUnlockingVault(true);
    setVaultUnlockError('');

    try {
      // Usar el servicio real para validar la contraseña del vault
      const result = await vaultService.unlockVault(vaultToUnlock.id, password);
      
      if (result.success) {
        // Marcar vault como desbloqueado
        markVaultAsUnlocked(vaultToUnlock.id);
        setSelectedVaultId(vaultToUnlock.id);
        setVaultPassword(password); // Guardar contraseña para enviar con el formulario
        
        setShowUnlockVault(false);
        setVaultToUnlock(null);
        setVaultUnlockError('');
        
        return { success: true, message: 'Vault desbloqueado correctamente' };
      } else {
        const errorMsg = result.error || 'Contraseña de vault incorrecta';
        setVaultUnlockError(errorMsg);
        throw new Error(errorMsg);
      }
    } catch (err) {
      const errorMsg = err instanceof Error ? err.message : 'Contraseña de vault incorrecta';
      setVaultUnlockError(errorMsg);
      return { success: false, message: errorMsg };
    } finally {
      setIsUnlockingVault(false);
    }
  };

  const generatePassword = () => {
    const length = 16;
    const charset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?';
    let password = '';
    
    const lowercase = 'abcdefghijklmnopqrstuvwxyz';
    const uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    const numbers = '0123456789';
    const symbols = '!@#$%^&*()_+-=[]{}|;:,.<>?';
    
    password += lowercase[Math.floor(Math.random() * lowercase.length)];
    password += uppercase[Math.floor(Math.random() * uppercase.length)];
    password += numbers[Math.floor(Math.random() * numbers.length)];
    password += symbols[Math.floor(Math.random() * symbols.length)];
    
    for (let i = password.length; i < length; i++) {
      password += charset[Math.floor(Math.random() * charset.length)];
    }
    
    const shuffled = password.split('').sort(() => Math.random() - 0.5).join('');
    handleInputChange('password', shuffled);
    setShowPassword(true);
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
      const cleanWebsite = formData.website.trim()
        .replace(/^https?:\/\//, '')
        .replace(/^www\./, '');

      const submitData: AddPasswordWithVaultData = {
        ...formData,
        website: cleanWebsite,
        username: formData.username.trim()
      };

      // Agregar información del vault si está seleccionado
      if (selectedVaultId) {
        submitData.vault_id = selectedVaultId;
        
        // Solo enviar vault_password si el vault es privado
        const selectedVault = vaults.find(v => v.id === selectedVaultId);
        if (selectedVault?.is_private) {
          // Si el vault es privado y ya está desbloqueado, no enviar contraseña
          if (isVaultUnlocked(selectedVaultId)) {
            // Vault ya desbloqueado - no se requiere contraseña
            submitData.vault_already_unlocked = true;
            // No incluir vault_password
          } else if (vaultPassword) {
            // Vault no desbloqueado pero tenemos contraseña (desde modal de unlock)
            submitData.vault_password = vaultPassword;
            submitData.vault_already_unlocked = false;
          } else {
            // Este caso no debería ocurrir, pero por seguridad
            submitData.vault_already_unlocked = false;
          }
        } else {
          // Vault público - siempre considerado "desbloqueado"
          submitData.vault_already_unlocked = true;
        }
      } else {
        // Asegurar que vault_id sea null cuando no hay vault seleccionado
        submitData.vault_id = null;
        submitData.vault_already_unlocked = false;
      }

      console.log('Submitting password data:', submitData);

      const result = await onSubmit(submitData);

      if (result.success) {
        
        setFormData({
          website: '',
          username: '',
          password: '',
          algorithm: 'AES'
        });
        setSelectedVaultId(preselectedVault?.id || null); // Mantener vault preseleccionado para siguientes
        setVaultPassword('');
        setIsVaultDropdownOpen(false);
        setShowPassword(false);
        setError('');
        setSuccessMessage('');
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
      if (isVaultDropdownOpen) {
        setIsVaultDropdownOpen(false);
      } else {
        onClose();
      }
    }
    if (e.key === 'Enter' && !isSubmitting && !validateForm() && !successMessage && !isVaultDropdownOpen) {
      handleSubmit();
    }
  };

  if (!isOpen) return null;

  const isFormValid = !validateForm() && !isSubmitting && !successMessage;
  const selectedVault = selectedVaultId ? vaults.find(v => v.id === selectedVaultId) : null;

  return (
    <>
      <div className="fixed inset-0 flex items-center justify-center p-4 z-50">
        <div 
          className="absolute inset-0"
          style={{
            backgroundColor: 'rgba(0, 0, 0, 0.4)',
            backdropFilter: 'blur(8px)',
            WebkitBackdropFilter: 'blur(8px)',
          }}
          onClick={() => !isSubmitting && !successMessage && onClose()}
        />
        
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
                style={{ 
                  backgroundColor: successMessage ? `${colors.success}20` : `${colors.primary}20`
                }}
              >
                {successMessage ? (
                  <CheckCircle className="w-5 h-5" style={{ color: colors.success }} />
                ) : (
                  <Plus className="w-5 h-5" style={{ color: colors.primary }} />
                )}
              </div>
              <h3 className="text-lg font-semibold" style={{ color: colors.textPrimary }}>
                {successMessage ? 'Contraseña Guardada' : (prefilledPassword ? 'Guardar Contraseña Generada' : 'Agregar Nueva Contraseña')}
              </h3>
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

          {/* Form Content */}
          {!successMessage && (
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
                    color: colors.textPrimary,
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

              {/* Vault Selection - SIMPLIFICADO */}
              <div>
                <label className="block text-sm font-medium mb-2" style={{ color: colors.textPrimary }}>
                  Vault de Destino
                </label>
                
                {vaultsLoading ? (
                  <div className="flex items-center justify-center py-3 px-3 rounded-lg border" style={{ borderColor: colors.border, backgroundColor: colors.background }}>
                    <Loader2 className="w-4 h-4 animate-spin mr-2" style={{ color: colors.primary }} />
                    <span className="text-sm" style={{ color: colors.textMuted }}>
                      Cargando vaults...
                    </span>
                  </div>
                ) : (
                  <div className="relative" ref={dropdownRef}>
                    {/* Combobox Button */}
                    <button
                      type="button"
                      onClick={() => setIsVaultDropdownOpen(!isVaultDropdownOpen)}
                      className="w-full px-3 py-2 text-left rounded-lg border focus:outline-none focus:ring-2 transition-all duration-200 flex items-center justify-between"
                      style={{
                        backgroundColor: colors.background,
                        borderColor: isVaultDropdownOpen ? colors.primary : colors.border,
                        color: colors.textPrimary
                      }}
                      disabled={isSubmitting}
                    >
                      {selectedVault ? (
                        <div className="flex items-center gap-2">
                          <div 
                            className="w-4 h-4 rounded-full flex items-center justify-center"
                            style={{ backgroundColor: VAULT_COLORS[selectedVault.color].bg }}
                          >
                            {selectedVault.is_private ? (
                              <Lock className="w-2 h-2 text-white" />
                            ) : (
                              <Folder className="w-2 h-2 text-white" />
                            )}
                          </div>
                          <span className="font-medium">{selectedVault.name}</span>
                          <span className="text-sm opacity-75">({selectedVault.password_count || 0})</span>
                        </div>
                      ) : (
                        <span style={{ color: colors.textMuted }}>Sin vault (General)</span>
                      )}
                      {isVaultDropdownOpen ? (
                        <ChevronUp className="w-4 h-4" style={{ color: colors.textMuted }} />
                      ) : (
                        <ChevronDown className="w-4 h-4" style={{ color: colors.textMuted }} />
                      )}
                    </button>

                    {/* Dropdown Menu */}
                    {isVaultDropdownOpen && (
                      <div 
                        className="absolute top-full left-0 right-0 mt-1 rounded-lg border shadow-lg z-10 max-h-48 overflow-y-auto"
                        style={{ 
                          backgroundColor: colors.surface,
                          borderColor: colors.border,
                          boxShadow: '0 10px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04)'
                        }}
                      >
                        {/* Opción "Sin vault" */}
                        <button
                          type="button"
                          onClick={() => handleVaultSelect(null)}
                          className="w-full text-left px-3 py-2 transition-colors duration-150 rounded-t-lg"
                          style={{
                            backgroundColor: selectedVaultId === null ? `${colors.primary}20` : 'transparent',
                            borderBottom: `1px solid ${colors.border}`
                          }}
                          onMouseEnter={(e) => {
                            if (selectedVaultId !== null) {
                              e.currentTarget.style.backgroundColor = `${colors.primary}08`;
                            }
                          }}
                          onMouseLeave={(e) => {
                            if (selectedVaultId !== null) {
                              e.currentTarget.style.backgroundColor = 'transparent';
                            }
                          }}
                          disabled={isSubmitting}
                        >
                          <div className="flex items-center gap-3">
                            <div 
                              className="w-6 h-6 rounded-full flex items-center justify-center flex-shrink-0"
                              style={{ backgroundColor: colors.textMuted }}
                            >
                              <Folder className="w-3 h-3 text-white" />
                            </div>
                            <div className="min-w-0 flex-1">
                              <span className="text-sm font-medium" style={{ color: colors.textPrimary }}>
                                Sin vault
                              </span>
                              <p className="text-xs" style={{ color: colors.textMuted }}>
                                Guardar en área general
                              </p>
                            </div>
                          </div>
                        </button>

                        {/* Vaults disponibles */}
                        {vaults.map((vault, index) => {
                          const colorScheme = VAULT_COLORS[vault.color];
                          const isSelected = selectedVaultId === vault.id;
                          
                          return (
                            <button
                              key={vault.id}
                              type="button"
                              onClick={() => handleVaultSelect(vault)}
                              className={`w-full text-left px-3 py-2 transition-colors duration-150 ${
                                index === vaults.length - 1 ? 'rounded-b-lg' : ''
                              }`}
                              style={{
                                backgroundColor: isSelected 
                                  ? `${colorScheme.bg}20` 
                                  : 'transparent',
                                borderBottom: index < vaults.length - 1 ? `1px solid ${colors.border}` : 'none'
                              }}
                              onMouseEnter={(e) => {
                                if (!isSelected) {
                                  e.currentTarget.style.backgroundColor = `${colors.primary}08`;
                                }
                              }}
                              onMouseLeave={(e) => {
                                if (!isSelected) {
                                  e.currentTarget.style.backgroundColor = 'transparent';
                                }
                              }}
                              disabled={isSubmitting}
                            >
                              <div className="flex items-center gap-3">
                                <div 
                                  className="w-6 h-6 rounded-full flex items-center justify-center flex-shrink-0"
                                  style={{ backgroundColor: colorScheme.bg }}
                                >
                                  {vault.is_private ? (
                                    <Lock className="w-3 h-3 text-white" />
                                  ) : (
                                    <Folder className="w-3 h-3 text-white" />
                                  )}
                                </div>
                                <div className="min-w-0 flex-1">
                                  <div className="flex items-center justify-between">
                                    <span className="text-sm font-medium truncate" style={{ color: colors.textPrimary }}>
                                      {vault.name}
                                    </span>
                                    {vault.is_private && !isVaultUnlocked(vault.id) && (
                                      <Lock className="w-3 h-3 ml-2 flex-shrink-0" style={{ color: colors.textMuted }} />
                                    )}
                                  </div>
                                  <p className="text-xs truncate" style={{ color: colors.textMuted }}>
                                    {vault.password_count || 0} contraseña{(vault.password_count || 0) !== 1 ? 's' : ''}
                                    {vault.description && ` • ${vault.description}`}
                                  </p>
                                </div>
                              </div>
                            </button>
                          );
                        })}
                      </div>
                    )}
                  </div>
                )}

                {/* Selected Vault Info */}
                {selectedVault && (
                  <div 
                    className="mt-3 p-3 rounded-lg border"
                    style={{ 
                      backgroundColor: `${VAULT_COLORS[selectedVault.color].bg}20`,
                      borderColor: VAULT_COLORS[selectedVault.color].border
                    }}
                  >
                    <div className="flex items-center gap-2">
                      <CheckCircle className="w-4 h-4" style={{ color: VAULT_COLORS[selectedVault.color].bg }} />
                      <span className="text-sm font-medium" style={{ color: colors.textPrimary }}>
                        Se guardará en: {selectedVault.name}
                      </span>
                    </div>
                    {selectedVault.description && (
                      <p className="text-xs mt-1 ml-6" style={{ color: colors.textMuted }}>
                        {selectedVault.description}
                      </p>
                    )}
                  </div>
                )}
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
          )}
        </div>
      </div>

      {/* Unlock Vault Modal */}
      <UnlockVaultModal
        isOpen={showUnlockVault}
        onClose={() => {
          setShowUnlockVault(false);
          setVaultToUnlock(null);

          // Si había un vault preseleccionado y no se desbloqueó, resetear
          if (preselectedVault && !isVaultUnlocked(preselectedVault.id)) {
            setSelectedVaultId(null);
            setVaultPassword('');
          }
        }}
        onSubmit={handleUnlockVault}
        vault={vaultToUnlock}
        loading={isUnlockingVault}
      />
    </>
  );
};