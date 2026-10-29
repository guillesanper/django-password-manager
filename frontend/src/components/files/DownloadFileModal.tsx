// components/files/DownloadFileModal.tsx
import React from 'react';
import { X, Download, AlertCircle, Loader2, Shield } from 'lucide-react';
import { useUnifiedTheme } from '../UnifiedThemeProvider';

interface DownloadFileModalProps {
  isOpen: boolean;
  onClose: () => void;
  onConfirm: () => void;
  fileName: string;
  loading?: boolean;
  error?: string;
}

export const DownloadFileModal: React.FC<DownloadFileModalProps> = ({
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
    <div className="download-modal-overlay" onClick={!loading ? onClose : undefined}>
      <div 
        className="download-modal-container"
        onClick={(e) => e.stopPropagation()}
        onKeyDown={handleKeyDown}
        style={{ 
          backgroundColor: colors.surface,
          borderColor: colors.border
        }}
      >
        {/* Header */}
        <div className="download-modal-header">
          <div className="download-modal-icon">
            <div style={{ backgroundColor: `${colors.primary}20` }}>
              <Download className="w-6 h-6" style={{ color: colors.primary }} />
            </div>
            <h3 style={{ color: colors.textPrimary }}>
              Descargar Archivo
            </h3>
          </div>
          {!loading && (
            <button
              onClick={onClose}
              className="download-modal-close"
              style={{ color: colors.textMuted }}
            >
              <X className="w-5 h-5" />
            </button>
          )}
        </div>

        {/* File Info */}
        <div 
          className="download-modal-file-info"
          style={{ 
            backgroundColor: colors.background,
            borderColor: colors.border
          }}
        >
          <div className="download-modal-file-icon">
            <Shield className="w-5 h-5" style={{ color: colors.info }} />
          </div>
          <div>
            <p 
              className="download-modal-file-name"
              style={{ color: colors.textPrimary }}
            >
              {fileName}
            </p>
            <p 
              className="download-modal-file-description"
              style={{ color: colors.textSecondary }}
            >
              El archivo será desencriptado antes de la descarga
            </p>
          </div>
        </div>

        {/* Form */}
        <form onSubmit={handleSubmit} className="download-modal-form">
          {/* Error Message */}
          {error && (
            <div 
              className="download-modal-error"
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
          <div className="download-modal-actions">
            <button
              type="button"
              onClick={onClose}
              className="download-modal-button-secondary"
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
              className="download-modal-button-primary"
              style={{ backgroundColor: colors.primary }}
              disabled={loading}
            >
              {loading ? (
                <div className="download-modal-loading">
                  <Loader2 className="w-4 h-4 animate-spin" />
                  Descargando...
                </div>
              ) : (
                <>
                  <Download className="w-4 h-4" />
                  Descargar
                </>
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};