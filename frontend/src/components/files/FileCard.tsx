// components/files/FileCard.tsx - Corregido
import React from 'react';
import { Download, Trash2, File, FileText, Image, Music, Video, Archive, Shield, Calendar, HardDrive } from 'lucide-react';
import { useUnifiedTheme } from '../UnifiedThemeProvider';
import { type EncryptedFile } from '../../services/fileService';

export interface FileCardProps {
  file: EncryptedFile;
  onDownload: (fileId: number) => void;
  onDelete: (fileId: number) => void;
}

export const FileCard: React.FC<FileCardProps> = ({
  file,
  onDownload,
  onDelete
}) => {
  const { colors } = useUnifiedTheme();

  // Función para obtener el icono basado en la extensión del archivo
  const getFileIcon = (filename: string) => {
    const extension = filename.split('.').pop()?.toLowerCase();
    
    switch (extension) {
      case 'txt':
      case 'doc':
      case 'docx':
      case 'pdf':
        return FileText;
      case 'jpg':
      case 'jpeg':
      case 'png':
      case 'gif':
      case 'svg':
      case 'webp':
        return Image;
      case 'mp3':
      case 'wav':
      case 'ogg':
      case 'flac':
        return Music;
      case 'mp4':
      case 'avi':
      case 'mkv':
      case 'mov':
        return Video;
      case 'zip':
      case 'rar':
      case '7z':
      case 'tar':
        return Archive;
      default:
        return File;
    }
  };

  const FileIcon = getFileIcon(file.title);

  // Función para formatear la fecha
  const formatDate = (dateString: string) => {
    const date = new Date(dateString);
    return new Intl.DateTimeFormat('es-ES', {
      day: '2-digit',
      month: '2-digit',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    }).format(date);
  };

  // Función para obtener color del algoritmo
  const getAlgorithmColor = (algorithm: string) => {
    switch (algorithm) {
      case 'AES':
        return colors.info;
      case 'ChaCha20':
        return colors.success;
      case 'Blowfish':
        return colors.warning;
      default:
        return colors.textMuted;
    }
  };

  return (
    <div 
      className="file-card group"
      style={{ 
        backgroundColor: colors.surface,
        borderColor: colors.border
      }}
    >
      {/* Header del archivo */}
      <div className="file-card-header">
        <div className="file-card-info">
          <div 
            className="file-card-icon"
            style={{ backgroundColor: `${colors.primary}15` }}
          >
            <FileIcon 
              className="w-6 h-6" 
              style={{ color: colors.primary }} 
            />
          </div>
          <div className="file-card-details">
            <h3 
              className="file-card-title"
              style={{ color: colors.textPrimary }}
              title={file.title}
            >
              {file.title}
            </h3>
            <div className="file-card-meta">
              <span 
                className="file-card-algorithm"
                style={{ 
                  backgroundColor: `${getAlgorithmColor(file.algorithm)}20`,
                  color: getAlgorithmColor(file.algorithm)
                }}
              >
                {file.algorithm}
              </span>
              <div className="file-card-security">
                <Shield className="w-3 h-3" style={{ color: colors.success }} />
                <span style={{ color: colors.textSecondary }}>
                  Encriptado
                </span>
              </div>
            </div>
          </div>
        </div>
        
        {/* Acciones */}
        <div className="file-card-actions">
          <button
            onClick={() => onDownload(file.id)}
            className="file-card-action-button file-card-download"
            style={{ color: colors.primary }}
            title="Descargar archivo"
          >
            <Download className="w-4 h-4" />
          </button>
          <button
            onClick={() => onDelete(file.id)}
            className="file-card-action-button file-card-delete"
            style={{ color: colors.error }}
            title="Eliminar archivo"
          >
            <Trash2 className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Información adicional */}
      <div className="file-card-body">
        <div className="file-card-info-grid">
          <div className="file-card-info-item">
            <Calendar className="w-4 h-4" style={{ color: colors.textMuted }} />
            <div>
              <span 
                className="file-card-info-label"
                style={{ color: colors.textSecondary }}
              >
                Subido:
              </span>
              <span 
                className="file-card-info-value"
                style={{ color: colors.textPrimary }}
              >
                {formatDate(file.uploaded_at)}
              </span>
            </div>
          </div>
          
          {/* Mostrar tamaño si está disponible */}
          {file.size_formatted && (
            <div className="file-card-info-item">
              <HardDrive className="w-4 h-4" style={{ color: colors.textMuted }} />
              <div>
                <span 
                  className="file-card-info-label"
                  style={{ color: colors.textSecondary }}
                >
                  Tamaño:
                </span>
                <span 
                  className="file-card-info-value"
                  style={{ color: colors.textPrimary }}
                >
                  {file.size_formatted}
                </span>
              </div>
            </div>
          )}
          
          {file.updated_at !== file.uploaded_at && (
            <div className="file-card-info-item">
              <Calendar className="w-4 h-4" style={{ color: colors.textMuted }} />
              <div>
                <span 
                  className="file-card-info-label"
                  style={{ color: colors.textSecondary }}
                >
                  Actualizado:
                </span>
                <span 
                  className="file-card-info-value"
                  style={{ color: colors.textPrimary }}
                >
                  {formatDate(file.updated_at)}
                </span>
              </div>
            </div>
          )}
        </div>

        {/* Mostrar error de MinIO si existe */}
        {file.minio_error && (
          <div 
            className="file-card-warning"
            style={{ 
              backgroundColor: `${colors.warning}20`,
              borderColor: colors.warning,
              color: colors.warning
            }}
          >
            <span className="text-xs">Error de sincronización con almacenamiento</span>
          </div>
        )}
      </div>

      {/* Indicador de hover */}
      <div 
        className="file-card-hover-indicator group-hover:opacity-100"
        style={{ backgroundColor: `${colors.primary}10` }}
      />
    </div>
  );
};