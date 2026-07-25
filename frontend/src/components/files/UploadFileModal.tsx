// components/files/UploadFileModal.tsx
import React, { useState, useEffect, useRef } from 'react';
import { X, Upload, FileText, AlertCircle, Loader2 } from 'lucide-react';
import { useUnifiedTheme } from '../UnifiedThemeProvider';

export interface UploadFileData {
  file: File;
}

interface UploadFileModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSubmit: (fileData: UploadFileData) => Promise<{ success: boolean; error?: string }>;
  loading?: boolean;
}

export const UploadFileModal: React.FC<UploadFileModalProps> = ({
  isOpen,
  onClose,
  onSubmit,
  loading = false
}) => {
  const { colors } = useUnifiedTheme();
  const fileInputRef = useRef<HTMLInputElement>(null);
  
  // Form state
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [error, setError] = useState('');
  const [dragActive, setDragActive] = useState(false);

  // Reset form when modal opens/closes
  useEffect(() => {
    if (!isOpen) {
      setSelectedFile(null);
      setError('');
      setDragActive(false);
      if (fileInputRef.current) {
        fileInputRef.current.value = '';
      }
    }
  }, [isOpen]);

  const handleFileSelect = (file: File) => {
    setSelectedFile(file);
    setError('');
  };

  const handleFileInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      handleFileSelect(file);
    }
  };

  const handleDrag = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true);
    } else if (e.type === 'dragleave') {
      setDragActive(false);
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);

    const files = e.dataTransfer.files;
    if (files && files[0]) {
      handleFileSelect(files[0]);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    
    if (!selectedFile) {
      setError('Selecciona un archivo');
      return;
    }

    setError('');

    try {
      const result = await onSubmit({ file: selectedFile });

      if (result.success) {
        onClose();
      } else {
        setError(result.error || 'Error al subir el archivo');
      }
    } catch (err) {
      setError('Error de conexión');
    }
  };

  const formatFileSize = (bytes: number): string => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  const getFileTypeColor = (filename: string): string => {
    const extension = filename.split('.').pop()?.toLowerCase();
    
    switch (extension) {
      case 'pdf':
      case 'doc':
      case 'docx':
        return 'text-red-600 bg-red-100';
      case 'jpg':
      case 'jpeg':
      case 'png':
      case 'gif':
        return 'text-purple-600 bg-purple-100';
      case 'mp3':
      case 'wav':
        return 'text-green-600 bg-green-100';
      case 'mp4':
      case 'avi':
        return 'text-blue-600 bg-blue-100';
      case 'zip':
      case 'rar':
        return 'text-orange-600 bg-orange-100';
      default:
        return 'text-gray-600 bg-gray-100';
    }
  };

  if (!isOpen) return null;

  return (
    <div className="upload-modal-overlay" onClick={!loading ? onClose : undefined}>
      <div 
        className="upload-modal-container"
        onClick={(e) => e.stopPropagation()}
        style={{ 
          backgroundColor: colors.surface,
          borderColor: colors.border
        }}
      >
        {/* Header */}
        <div className="upload-modal-header">
          <div className="upload-modal-icon">
            <div style={{ backgroundColor: `${colors.primary}20` }}>
              <Upload className="w-6 h-6" style={{ color: colors.primary }} />
            </div>
            <h3 style={{ color: colors.textPrimary }}>
              Subir Archivo Encriptado
            </h3>
          </div>
          {!loading && (
            <button
              onClick={onClose}
              className="upload-modal-close"
              style={{ color: colors.textMuted }}
            >
              <X className="w-5 h-5" />
            </button>
          )}
        </div>

        {/* Description */}
        <p style={{ color: colors.textSecondary, marginBottom: '1.5rem' }}>
          Sube un archivo para encriptarlo de forma segura
        </p>

        {/* Form */}
        <form onSubmit={handleSubmit} className="upload-modal-form">
          {/* File Drop Zone */}
          <div
            className={`upload-drop-zone ${dragActive ? 'active' : ''}`}
            style={{
              backgroundColor: dragActive ? `${colors.primary}10` : colors.background,
              borderColor: dragActive ? colors.primary : colors.border
            }}
            onDragEnter={handleDrag}
            onDragLeave={handleDrag}
            onDragOver={handleDrag}
            onDrop={handleDrop}
            onClick={() => fileInputRef.current?.click()}
          >
            <input
              ref={fileInputRef}
              type="file"
              onChange={handleFileInputChange}
              className="hidden"
              disabled={loading}
            />
            
            {selectedFile ? (
              <div className="upload-file-preview">
                <div 
                  className={`upload-file-icon ${getFileTypeColor(selectedFile.name)}`}
                >
                  <FileText className="w-8 h-8" />
                </div>
                <div className="upload-file-info">
                  <p 
                    className="upload-file-name"
                    style={{ color: colors.textPrimary }}
                  >
                    {selectedFile.name}
                  </p>
                  <p 
                    className="upload-file-size"
                    style={{ color: colors.textSecondary }}
                  >
                    {formatFileSize(selectedFile.size)}
                  </p>
                </div>
              </div>
            ) : (
              <div className="upload-placeholder">
                <Upload 
                  className="upload-placeholder-icon" 
                  style={{ color: colors.textMuted }} 
                />
                <p 
                  className="upload-placeholder-text"
                  style={{ color: colors.textPrimary }}
                >
                  Arrastra un archivo aquí o haz clic para seleccionar
                </p>
                <p 
                  className="upload-placeholder-subtext"
                  style={{ color: colors.textSecondary }}
                >
                  Máximo 100MB
                </p>
              </div>
            )}
          </div>

          {/* El contenido se cifra en el navegador con AES-256-GCM usando la VaultKey ya
              desbloqueada; no se pide contraseña ni se elige algoritmo. */}

          {/* Error Message */}
          {error && (
            <div 
              className="upload-modal-error"
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
          <div className="upload-modal-actions">
            <button
              type="button"
              onClick={onClose}
              className="upload-modal-button-secondary"
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
              className="upload-modal-button-primary"
              style={{ backgroundColor: colors.primary }}
              disabled={loading || !selectedFile}
            >
              {loading ? (
                <div className="upload-modal-loading">
                  <Loader2 className="w-4 h-4 animate-spin" />
                  Subiendo...
                </div>
              ) : (
                <>
                  <Upload className="w-4 h-4" />
                  Subir Archivo
                </>
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};