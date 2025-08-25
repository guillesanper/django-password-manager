// components/account/UnlockModal.tsx
import React, { useState, useEffect } from 'react';
import { X, Unlock, AlertCircle, Loader2 } from 'lucide-react';
import { useUnifiedTheme } from '../../theme/UnifiedThemeProvider';

interface UnlockModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSubmit: (masterPassword: string) => void;
  loading?: boolean;
  error?: string;
}

export const UnlockModal: React.FC<UnlockModalProps> = ({
  isOpen,
  onClose,
  onSubmit,
  loading = false,
  error = ''
}) => {
  const { colors } = useUnifiedTheme();
  const [masterPassword, setMasterPassword] = useState('');

  // Reset form when modal opens/closes
  useEffect(() => {
    if (!isOpen) {
      setMasterPassword('');
    }
  }, [isOpen]);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (masterPassword.trim() && !loading) {
      onSubmit(masterPassword.trim());
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Escape' && !loading) {
      onClose();
    }
  };

  if (!isOpen) return null;

  return (
    <div className="unlock-modal-overlay" onClick={!loading ? onClose : undefined}>
      <div 
        className="unlock-modal-container"
        onClick={(e) => e.stopPropagation()}
        onKeyDown={handleKeyDown}
        style={{ 
          backgroundColor: colors.surface,
          borderColor: colors.border
        }}
      >
        {/* Header */}
        <div className="unlock-modal-header">
          <div className="unlock-modal-icon">
            <div style={{ backgroundColor: `${colors.primary}20` }}>
              <Unlock className="w-6 h-6" style={{ color: colors.primary }} />
            </div>
            <h3 style={{ color: colors.textPrimary }}>
              Desbloquear Contraseña
            </h3>
          </div>
          {!loading && (
            <button
              onClick={onClose}
              className="unlock-modal-close"
              style={{ color: colors.textMuted }}
            >
              <X className="w-5 h-5" />
            </button>
          )}
        </div>

        {/* Description */}
        <p style={{ color: colors.textSecondary, marginBottom: '1.5rem' }}>
          Ingresa tu contraseña maestra para ver la contraseña
        </p>

        {/* Form */}
        <form onSubmit={handleSubmit} className="unlock-modal-form">
          <div className="unlock-modal-field">
            <label 
              htmlFor="masterPassword"
              style={{ color: colors.textPrimary }}
            >
              Contraseña Maestra
            </label>
            <input
              id="masterPassword"
              type="password"
              value={masterPassword}
              onChange={(e) => setMasterPassword(e.target.value)}
              placeholder="Ingresa tu contraseña maestra"
              className="unlock-modal-input"
              style={{
                backgroundColor: colors.background,
                borderColor: error ? colors.error : colors.border,
                color: colors.textPrimary
              }}
              disabled={loading}
              autoFocus
              required
            />
          </div>

          {/* Error Message */}
          {error && (
            <div 
              className="unlock-modal-error"
              style={{ 
                backgroundColor: `${colors.error}20`,
                borderColor: colors.error,
                color: colors.error
              }}
            >
              <AlertCircle className="w-4 h-4" />
              <span>{error}</span>
            </div>
          )}

          {/* Actions */}
          <div className="unlock-modal-actions">
            <button
              type="button"
              onClick={onClose}
              className="unlock-modal-button-secondary"
              style={{
                backgroundColor: colors.background,
                borderColor: colors.border,
                color: colors.textSecondary
              }}
              disabled={loading}
            >
              Cancelar
            </button>
            <button
              type="submit"
              className="unlock-modal-button-primary"
              style={{ backgroundColor: colors.primary }}
              disabled={loading || !masterPassword.trim()}
            >
              {loading ? (
                <div className="unlock-modal-loading">
                  <Loader2 className="w-4 h-4 animate-spin" />
                  Desbloqueando...
                </div>
              ) : (
                <>
                  <Unlock className="w-4 h-4" />
                  Desbloquear
                </>
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};