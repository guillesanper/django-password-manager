// components/account/DeleteConfirmModal.tsx
import React, { useState, useEffect } from 'react';
import { X, Trash2, AlertTriangle, Loader2 } from 'lucide-react';
import { useUnifiedTheme } from '../UnifiedThemeProvider';

interface DeleteConfirmModalProps {
  isOpen: boolean;
  onClose: () => void;
  onConfirm: () => void;
  accountName: string;
  loading?: boolean;
  error?: string;
}

export const DeleteConfirmModal: React.FC<DeleteConfirmModalProps> = ({
  isOpen,
  onClose,
  onConfirm,
  accountName,
  loading = false,
  error = ''
}) => {
  const { colors } = useUnifiedTheme();
  const [confirmText, setConfirmText] = useState('');

  const expectedConfirmText = 'ELIMINAR';

  // Reset form when modal opens/closes
  useEffect(() => {
    if (!isOpen) {
      setConfirmText('');
    }
  }, [isOpen]);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (confirmText === expectedConfirmText && !loading) {
      onConfirm();
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Escape' && !loading) {
      onClose();
    }
  };

  const isFormValid = confirmText === expectedConfirmText;

  if (!isOpen) return null;

  return (
    <div className="delete-modal-overlay" onClick={!loading ? onClose : undefined}>
      <div 
        className="delete-modal-container"
        onClick={(e) => e.stopPropagation()}
        onKeyDown={handleKeyDown}
        style={{ 
          backgroundColor: colors.surface,
          borderColor: colors.border
        }}
      >
        {/* Header */}
        <div className="delete-modal-header">
          <div className="delete-modal-icon">
            <div style={{ backgroundColor: `${colors.error}20` }}>
              <Trash2 className="w-6 h-6" style={{ color: colors.error }} />
            </div>
            <h3 style={{ color: colors.textPrimary }}>
              Eliminar Contraseña
            </h3>
          </div>
          {!loading && (
            <button
              onClick={onClose}
              className="delete-modal-close"
              style={{ color: colors.textMuted }}
            >
              <X className="w-5 h-5" />
            </button>
          )}
        </div>

        {/* Content */}
        <div className="delete-modal-content">
          <p style={{ color: colors.textPrimary }}>
            Estás a punto de eliminar la contraseña para{' '}
            <strong>{accountName}</strong>
          </p>
          <p className="delete-modal-warning" style={{ color: colors.textSecondary }}>
            Esta acción es permanente y no podrá ser revertida.
          </p>
        </div>

        {/* Form */}
        <form onSubmit={handleSubmit} className="delete-modal-form">
          <div className="delete-modal-field">
            <label 
              htmlFor="confirmText"
              style={{ color: colors.textPrimary }}
            >
              Para confirmar, escribe <strong>ELIMINAR</strong> en el campo:
            </label>
            <input
              id="confirmText"
              type="text"
              value={confirmText}
              onChange={(e) => setConfirmText(e.target.value)}
              placeholder="Escribe ELIMINAR"
              className="delete-modal-input"
              style={{
                backgroundColor: colors.background,
                borderColor: colors.border,
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
              className="delete-modal-error"
              style={{ 
                backgroundColor: `${colors.error}20`,
                borderColor: colors.error,
                color: colors.error
              }}
            >
              <AlertTriangle className="w-4 h-4" />
              <span>{error}</span>
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
              type="submit"
              className="modal-btn modal-btn--danger"
              disabled={loading || !isFormValid}
            >
              {loading ? (
                <div className="delete-modal-loading">
                  <Loader2 className="w-4 h-4 animate-spin" />
                  Eliminando...
                </div>
              ) : (
                <>
                  <Trash2 className="w-4 h-4" />
                  Eliminar Contraseña
                </>
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};