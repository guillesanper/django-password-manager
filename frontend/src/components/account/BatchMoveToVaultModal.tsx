// components/account/BatchMoveToVaultModal.tsx
import React, { useState, useEffect, useRef } from 'react';
import { X, FolderOpen, ChevronDown, ChevronUp, Lock, Folder, AlertTriangle, Loader2 } from 'lucide-react';
import { useUnifiedTheme } from '../../theme/UnifiedThemeProvider';
import { useVaults } from '../hooks/useVaults';
import { UnlockVaultModal } from '../vaults/UnlockVaultModal';
import { VAULT_COLORS, type Vault } from '../../services/vaultService';

interface BatchMoveToVaultModalProps {
  isOpen: boolean;
  onClose: () => void;
  onConfirm: (vaultId: number | null, vaultPassword?: string) => void;
  selectedCount: number;
  loading?: boolean;
  error?: string;
}

export const BatchMoveToVaultModal: React.FC<BatchMoveToVaultModalProps> = ({
  isOpen,
  onClose,
  onConfirm,
  selectedCount,
  loading = false,
  error = ''
}) => {
  const { colors } = useUnifiedTheme();
  const { vaults, loading: vaultsLoading, isVaultUnlocked } = useVaults();
  const dropdownRef = useRef<HTMLDivElement>(null);
  
  const [selectedVaultId, setSelectedVaultId] = useState<number | null>(null);
  const [isVaultDropdownOpen, setIsVaultDropdownOpen] = useState(false);
  const [showUnlockVault, setShowUnlockVault] = useState(false);
  const [vaultToUnlock, setVaultToUnlock] = useState<Vault | null>(null);
  const [vaultPassword, setVaultPassword] = useState('');
  const [isUnlockingVault, setIsUnlockingVault] = useState(false);
  const [vaultUnlockError, setVaultUnlockError] = useState('');

  // Reset form when modal opens/closes
  useEffect(() => {
    if (!isOpen) {
      setSelectedVaultId(null);
      setIsVaultDropdownOpen(false);
      setShowUnlockVault(false);
      setVaultToUnlock(null);
      setVaultPassword('');
      setVaultUnlockError('');
    }
  }, [isOpen]);

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

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Escape' && !loading && !isUnlockingVault) {
      if (isVaultDropdownOpen) {
        setIsVaultDropdownOpen(false);
      } else {
        onClose();
      }
    }
  };

  const handleVaultSelect = (vault: Vault | null) => {
    setIsVaultDropdownOpen(false);
    
    if (!vault) {
      // Sin vault seleccionado (mover a área general)
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
      setVaultPassword('');
    }
  };

  const handleUnlockVault = async (password: string) => {
    if (!vaultToUnlock) return { success: false, message: 'No hay vault para desbloquear' };
    
    setIsUnlockingVault(true);
    setVaultUnlockError('');

    try {
      // Aquí deberías usar tu servicio real para validar la contraseña del vault
      // Por ahora simulo una validación exitosa
      await new Promise(resolve => setTimeout(resolve, 1000));
      
      setSelectedVaultId(vaultToUnlock.id);
      setVaultPassword(password);
      
      setShowUnlockVault(false);
      setVaultToUnlock(null);
      setVaultUnlockError('');
      
      return { success: true, message: 'Vault desbloqueado correctamente' };
    } catch (err) {
      const errorMsg = 'Contraseña de vault incorrecta';
      setVaultUnlockError(errorMsg);
      return { success: false, message: errorMsg };
    } finally {
      setIsUnlockingVault(false);
    }
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!loading && !isUnlockingVault) {
      // Pasar el vaultPassword solo si hay uno seleccionado y es privado
      const selectedVault = selectedVaultId ? vaults.find(v => v.id === selectedVaultId) : null;
      const passwordToSend = selectedVault?.is_private ? vaultPassword : undefined;
      
      onConfirm(selectedVaultId, passwordToSend);
    }
  };

  const selectedVault = selectedVaultId ? vaults.find(v => v.id === selectedVaultId) : null;
  const isFormValid = selectedVaultId !== undefined; // null es válido (sin vault)

  if (!isOpen) return null;

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
          onClick={() => !loading && !isUnlockingVault && onClose()}
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
                style={{ backgroundColor: `${colors.primary}20` }}
              >
                <FolderOpen className="w-5 h-5" style={{ color: colors.primary }} />
              </div>
              <h3 className="text-lg font-semibold" style={{ color: colors.textPrimary }}>
                Mover Contraseñas a Vault
              </h3>
            </div>
            {!loading && !isUnlockingVault && (
              <button
                onClick={onClose}
                className="p-1 hover:bg-opacity-80 rounded transition-colors"
                style={{ color: colors.textMuted }}
              >
                <X className="w-5 h-5" />
              </button>
            )}
          </div>

          {/* Content */}
          <form onSubmit={handleSubmit} className="p-6 space-y-4">
            <div className="text-sm mb-4" style={{ color: colors.textSecondary }}>
              Selecciona el vault de destino para <strong>{selectedCount} contraseña{selectedCount !== 1 ? 's' : ''}</strong>:
            </div>

            {/* Vault Selection */}
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
                    disabled={loading || isUnlockingVault}
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
                    ) : selectedVaultId === null ? (
                      <span style={{ color: colors.textMuted }}>Sin vault (Área General)</span>
                    ) : (
                      <span style={{ color: colors.textMuted }}>Seleccionar vault...</span>
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
                        disabled={loading || isUnlockingVault}
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
                              Mover al área general
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
                            disabled={loading || isUnlockingVault}
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
                    <FolderOpen className="w-4 h-4" style={{ color: VAULT_COLORS[selectedVault.color].bg }} />
                    <span className="text-sm font-medium" style={{ color: colors.textPrimary }}>
                      Se moverá a: {selectedVault.name}
                    </span>
                  </div>
                  {selectedVault.description && (
                    <p className="text-xs mt-1 ml-6" style={{ color: colors.textMuted }}>
                      {selectedVault.description}
                    </p>
                  )}
                </div>
              )}

              {/* Sin vault seleccionado info */}
              {selectedVaultId === null && (
                <div 
                  className="mt-3 p-3 rounded-lg border"
                  style={{ 
                    backgroundColor: `${colors.info}20`,
                    borderColor: colors.info
                  }}
                >
                  <div className="flex items-center gap-2">
                    <FolderOpen className="w-4 h-4" style={{ color: colors.info }} />
                    <span className="text-sm font-medium" style={{ color: colors.textPrimary }}>
                      Se moverá al área general (sin vault)
                    </span>
                  </div>
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
                disabled={loading || isUnlockingVault}
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
                disabled={!isFormValid || loading || isUnlockingVault}
              >
                {loading ? (
                  <>
                    <Loader2 className="w-4 h-4 animate-spin" />
                    Moviendo {selectedCount} contraseña{selectedCount !== 1 ? 's' : ''}...
                  </>
                ) : (
                  <>
                    <FolderOpen className="w-4 h-4" />
                    Mover {selectedCount} Contraseña{selectedCount !== 1 ? 's' : ''}
                  </>
                )}
              </button>
            </div>
          </form>
        </div>
      </div>

      {/* Unlock Vault Modal */}
      <UnlockVaultModal
        isOpen={showUnlockVault}
        onClose={() => {
          setShowUnlockVault(false);
          setVaultToUnlock(null);
          setVaultUnlockError('');
        }}
        onSubmit={handleUnlockVault}
        vault={vaultToUnlock}
        loading={isUnlockingVault}
      />
    </>
  );
};