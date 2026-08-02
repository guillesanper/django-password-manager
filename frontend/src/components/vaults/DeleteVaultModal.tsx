import React, { useState, useEffect } from 'react';
import { X, Trash2, AlertTriangle, Move, Loader2, Eye, EyeOff, Folder, Lock } from 'lucide-react';
import { useUnifiedTheme } from '../UnifiedThemeProvider';
import { VAULT_COLORS } from '../Sidebar';
import type { Vault } from '../../services/vaultService';

interface DeleteVaultModalProps {
  isOpen: boolean;
  onClose: () => void;
  onConfirm: (masterPassword: string, movePasswordsToVault?: number) => Promise<{ success: boolean; message?: string }>;
  vault: Vault | null;
  availableVaults: Vault[];
  loading?: boolean;
}

export const DeleteVaultModal: React.FC<DeleteVaultModalProps> = ({
  isOpen,
  onClose,
  onConfirm,
  vault,
  availableVaults,
  loading = false
}) => {
  const { colors } = useUnifiedTheme();
  const [masterPassword, setMasterPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [confirmText, setConfirmText] = useState('');
  const [movePasswordsToVault, setMovePasswordsToVault] = useState<number | null>(null);
  const [error, setError] = useState('');

  const expectedConfirmText = 'ELIMINAR';

  // Reset form when modal opens/closes
  useEffect(() => {
    if (!isOpen) {
      setMasterPassword('');
      setShowPassword(false);
      setConfirmText('');
      setMovePasswordsToVault(null);
      setError('');
    }
  }, [isOpen]);

  const handleSubmit = async () => {
    setError('');
    
    if (!masterPassword.trim()) {
      setError('La contraseña maestra es requerida');
      return;
    }
    
    if (confirmText !== expectedConfirmText) {
      setError('Debes escribir "ELIMINAR" para confirmar');
      return;
    }

    try {
      const result = await onConfirm(
        masterPassword.trim(), 
        movePasswordsToVault || undefined
      );
      
      if (result.success) {
        onClose();
      } else {
        setError(result.message || 'Error al eliminar el vault');
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Error al eliminar el vault');
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey && !loading && isFormValid) {
      e.preventDefault();
      handleSubmit();
    } else if (e.key === 'Escape' && !loading) {
      onClose();
    }
  };

  if (!isOpen || !vault) return null;

  const colorScheme = VAULT_COLORS[vault.color] || VAULT_COLORS.blue;
  const filteredVaults = availableVaults.filter(v => v.id !== vault.id);
  const hasPasswords = vault.password_count > 0;
  const isFormValid = masterPassword.trim() && confirmText === expectedConfirmText;

  return (
    <div className="fixed inset-0 flex items-center justify-center p-4 z-50">
      <div 
        className="absolute inset-0"
        style={{
          backgroundColor: 'rgba(0, 0, 0, 0.4)',
          backdropFilter: 'blur(8px)',
        }}
        onClick={!loading ? onClose : undefined}
      />
      <div 
        className="relative max-w-md w-full rounded-2xl shadow-2xl border p-6"
        onClick={(e) => e.stopPropagation()}
        onKeyDown={handleKeyDown}
        style={{ 
          backgroundColor: colors.surface,
          borderColor: colors.border,
        }}
      >
        {/* Header */}
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center space-x-3">
            <div 
              className="w-12 h-12 rounded-full flex items-center justify-center"
              style={{ backgroundColor: `${colors.error}20` }}
            >
              <Trash2 className="w-6 h-6" style={{ color: colors.error }} />
            </div>
            <div>
              <h3 className="text-xl font-semibold" style={{ color: colors.textPrimary }}>
                Eliminar Vault
              </h3>
              <p className="text-sm" style={{ color: colors.textMuted }}>
                Esta acción no se puede deshacer
              </p>
            </div>
          </div>
          {!loading && (
            <button
              onClick={onClose}
              className="p-2 rounded-lg transition-colors"
              style={{ color: colors.textMuted }}
            >
              <X className="w-5 h-5" />
            </button>
          )}
        </div>

        {/* Vault info */}
        <div 
          className="mb-6 p-4 rounded-lg border"
          style={{ 
            backgroundColor: `${colorScheme.color}10`,
            borderColor: `${colorScheme.color}30`
          }}
        >
          <div className="flex items-center space-x-3">
            <div 
              className="w-10 h-10 rounded-full flex items-center justify-center"
              style={{ backgroundColor: colorScheme.color }}
            >
              {vault.is_private ? (
                <Lock className="w-5 h-5 text-white" />
              ) : (
                <Folder className="w-5 h-5 text-white" />
              )}
            </div>
            <div>
              <h4 className="font-semibold" style={{ color: colors.textPrimary }}>
                {vault.name}
              </h4>
              <p className="text-sm" style={{ color: colors.textSecondary }}>
                {vault.password_count} contraseña{vault.password_count !== 1 ? 's' : ''}
                {vault.is_private ? ' • Privado' : ' • Público'}
              </p>
            </div>
          </div>
        </div>

        {/* Warning */}
        <div 
          className="mb-6 p-4 rounded-lg border flex items-start space-x-3"
          style={{ 
            backgroundColor: `${colors.warning}20`,
            borderColor: `${colors.warning}40`
          }}
        >
          <AlertTriangle className="w-5 h-5 mt-0.5" style={{ color: colors.warning }} />
          <div>
            <p className="text-sm font-medium" style={{ color: colors.textPrimary }}>
              ¿Qué pasará con las contraseñas?
            </p>
            <p className="text-sm mt-1" style={{ color: colors.textSecondary }}>
              {hasPasswords 
                ? 'Este vault contiene contraseñas. Elige qué hacer con ellas antes de continuar.'
                : 'Este vault está vacío y se eliminará completamente.'
              }
            </p>
          </div>
        </div>

        <div className="space-y-4">
          {/* Password destination (solo si tiene contraseñas) */}
          {hasPasswords && (
            <div>
              <label className="block text-sm font-medium mb-3" style={{ color: colors.textSecondary }}>
                ¿Qué hacer con las {vault.password_count} contraseña{vault.password_count !== 1 ? 's' : ''}?
              </label>
              <div className="space-y-2">
                {/* Opción: Eliminar contraseñas */}
                <label className="flex items-start space-x-3 cursor-pointer">
                  <input
                    type="radio"
                    name="passwordDestination"
                    checked={movePasswordsToVault === null}
                    onChange={() => setMovePasswordsToVault(null)}
                    className="mt-0.5"
                    disabled={loading}
                  />
                  <div>
                    <div className="flex items-center space-x-2">
                      <Trash2 className="w-4 h-4" style={{ color: colors.error }} />
                      <span className="text-sm font-medium" style={{ color: colors.textPrimary }}>
                        Eliminar todas las contraseñas
                      </span>
                    </div>
                    <p className="text-xs mt-1" style={{ color: colors.textMuted }}>
                      Las contraseñas se eliminarán permanentemente
                    </p>
                  </div>
                </label>

                {/* Opción: Mover a otro vault */}
                {filteredVaults.length > 0 && (
                  <label className="flex items-start space-x-3 cursor-pointer">
                    <input
                      type="radio"
                      name="passwordDestination"
                      checked={movePasswordsToVault !== null}
                      onChange={() => setMovePasswordsToVault(filteredVaults[0]?.id || null)}
                      className="mt-0.5"
                      disabled={loading}
                    />
                    <div className="flex-1">
                      <div className="flex items-center space-x-2">
                        <Move className="w-4 h-4" style={{ color: colors.primary }} />
                        <span className="text-sm font-medium" style={{ color: colors.textPrimary }}>
                          Mover a otro vault
                        </span>
                      </div>
                      <p className="text-xs mt-1 mb-2" style={{ color: colors.textMuted }}>
                        Las contraseñas se moverán al vault seleccionado
                      </p>
                      
                      {/* Selector de vault destino */}
                      {movePasswordsToVault !== null && (
                        <select
                          value={movePasswordsToVault || ''}
                          onChange={(e) => setMovePasswordsToVault(Number(e.target.value))}
                          className="w-full px-3 py-2 text-sm rounded-lg border"
                          style={{
                            backgroundColor: colors.background,
                            borderColor: colors.border,
                            color: colors.textPrimary
                          }}
                          disabled={loading}
                        >
                          {filteredVaults.map((v) => (
                            <option key={v.id} value={v.id}>
                              {v.name} ({v.password_count} contraseñas)
                            </option>
                          ))}
                        </select>
                      )}
                    </div>
                  </label>
                )}
              </div>
            </div>
          )}

          {/* Confirmation text */}
          <div>
            <label className="block text-sm font-medium mb-2" style={{ color: colors.textSecondary }}>
              Para confirmar, escribe <strong>ELIMINAR</strong>
            </label>
            <input
              type="text"
              value={confirmText}
              onChange={(e) => setConfirmText(e.target.value)}
              placeholder="Escribe ELIMINAR"
              className="w-full px-3 py-2 rounded-lg border focus:outline-none focus:ring-2"
              style={{
                backgroundColor: colors.background,
                borderColor: colors.border,
                color: colors.textPrimary
              }}
              disabled={loading}
            />
          </div>

          {/* Master password */}
          <div>
            <label className="block text-sm font-medium mb-2" style={{ color: colors.textSecondary }}>
              Contraseña Maestra *
            </label>
            <div className="relative">
              <input
                type={showPassword ? "text" : "password"}
                value={masterPassword}
                onChange={(e) => setMasterPassword(e.target.value)}
                placeholder="Ingresa tu contraseña maestra"
                className="w-full px-3 py-2 pr-10 rounded-lg border focus:outline-none focus:ring-2"
                style={{
                  backgroundColor: colors.background,
                  borderColor: error ? colors.error : colors.border,
                  color: colors.textPrimary
                }}
                disabled={loading}
              />
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                className="absolute right-3 top-1/2 transform -translate-y-1/2"
                style={{ color: colors.textMuted }}
                disabled={loading}
              >
                {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
              </button>
            </div>
          </div>

          {/* Error */}
          {error && (
            <div 
              className="p-3 rounded-lg border flex items-center space-x-2"
              style={{ 
                backgroundColor: `${colors.error}20`,
                borderColor: colors.error
              }}
            >
              <AlertTriangle className="w-4 h-4" style={{ color: colors.error }} />
              <span className="text-sm" style={{ color: colors.error }}>
                {error}
              </span>
            </div>
          )}

          {/* Actions */}
          <div className="modal-btn-row">
            <button
              type="button"
              onClick={onClose}
              className="modal-btn modal-btn--secondary"
              disabled={loading}
            >
              Cancelar
            </button>
            <button
              type="button"
              onClick={handleSubmit}
              className="modal-btn modal-btn--danger"
              disabled={loading || !isFormValid}
            >
              {loading ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  <span>Eliminando...</span>
                </>
              ) : (
                <>
                  <Trash2 className="w-4 h-4" />
                  <span>Eliminar Vault</span>
                </>
              )}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};