// components/files/DeleteFileModal.tsx
import React from 'react';
import { X, Trash2, AlertTriangle, Loader2 } from 'lucide-react';
import { useUnifiedTheme } from '../UnifiedThemeProvider';

interface DeleteFileModalProps {
  isOpen: boolean;
  onClose: () => void;
  onConfirm: () => void;
  fileName: string;
  loading?: boolean;
  error?: string;
}

export const DeleteFileModal: React.FC<DeleteFileModalProps> = ({
  isOpen,
  onClose,
  onConfirm,
  fileName,
  loading = false,
  error = ''
}) => {
  const { colors } = useUnifiedTheme();

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!loading) {
      onConfirm();
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Escape' && !loading) {
      onClose();
    }
  };

  if (!isOpen) return null;

  return (
    <div className="delete-file-modal-overlay" onClick={!loading ? onClose : undefined}>
      <div 
        className="delete-file-modal-container"
        onClick={(e) => e.stopPropagation()}
        onKeyDown={handleKeyDown}
        style={{ 
          backgroundColor: colors.surface,
          borderColor: colors.border
        }}
      >
        {/* Header */}
        <div className="delete-file-modal-header">
          <div className="delete-file-modal-icon">
            <div style={{ backgroundColor: `${colors.error}20` }}>
              <Trash2 className="w-6 h-6" style={{ color: colors.error }} />
            </div>
            <h3 style={{ color: colors.textPrimary }}>
              Eliminar Archivo
            </h3>
          </div>
          {!loading && (
            <button
              onClick={onClose}
              className="delete-file-modal-close"
              style={{ color: colors.textMuted }}
            >
              <X className="w-5 h-5" />
            </button>
          )}
        </div>

        {/* Warning */}
        <div 
          className="delete-file-modal-warning"
          style={{ 
            backgroundColor: `${colors.warning}20`,
            borderColor: colors.warning
          }}
        >
          <AlertTriangle className="w-5 h-5" style={{ color: colors.warning }} />
          <div>
            <p style={{ color: colors.textPrimary, fontWeight: '600' }}>
              ¡Cuidado! Esta acción no se puede deshacer
            </p>
            <p style={{ color: colors.textSecondary }}>
              El archivo "{fileName}" será eliminado permanentemente del servidor
            </p>
          </div>
        </div>

        {/* Form */}
        <form onSubmit={handleSubmit} className="delete-file-modal-form">
          {/* Error Message */}
          {error && (
            <div 
              className="delete-file-modal-error"
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
          <div className="delete-file-modal-actions">
            <button
              type="button"
              onClick={onClose}
              className="delete-file-modal-button-secondary"
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
              className="delete-file-modal-button-primary"
              style={{ backgroundColor: colors.error }}
              disabled={loading}
            >
              {loading ? (
                <div className="delete-file-modal-loading">
                  <Loader2 className="w-4 h-4 animate-spin" />
                  Eliminando...
                </div>
              ) : (
                <>
                  <Trash2 className="w-4 h-4" />
                  Eliminar Archivo
                </>
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};