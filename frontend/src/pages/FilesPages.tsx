// pages/FilesPage.tsx - Corregido
import React, { useState, useCallback } from 'react';
import { Search, Upload, RefreshCw, Folder, SortAsc, SortDesc } from 'lucide-react';
import { useUnifiedTheme } from '../theme/UnifiedThemeProvider';
import { useFiles } from '../components/hooks/useFiles';

// Import de los componentes de archivos
import {
  FileCard,
  UploadFileModal,
  DownloadFileModal,
  DeleteFileModal,
  FileStats,
  type UploadFileData
} from '../components/files';

// Tipos de ordenamiento
type SortBy = 'title' | 'uploaded_at' | 'algorithm';
type SortOrder = 'asc' | 'desc';

export const FilesPage: React.FC = () => {
  const { colors } = useUnifiedTheme();
  const {
    files,
    loading,
    error,
    uploadFile,
    downloadFile,
    deleteFile,
    reloadFiles
  } = useFiles();

  // Estados locales
  const [searchTerm, setSearchTerm] = useState('');
  const [sortBy, setSortBy] = useState<SortBy>('uploaded_at');
  const [sortOrder, setSortOrder] = useState<SortOrder>('desc');
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  // Estados de modales
  const [showUploadModal, setShowUploadModal] = useState(false);
  const [showDownloadModal, setShowDownloadModal] = useState(false);
  const [showDeleteModal, setShowDeleteModal] = useState(false);
  
  const [selectedFileId, setSelectedFileId] = useState<number | null>(null);
  
  // Estados de errores y loading
  const [uploadError, setUploadError] = useState('');
  const [downloadError, setDownloadError] = useState('');
  const [deleteError, setDeleteError] = useState('');
  
  const [uploadLoading, setUploadLoading] = useState(false);
  const [downloadLoading, setDownloadLoading] = useState(false);
  const [deleteLoading, setDeleteLoading] = useState(false);

  // Handlers para modales
  const handleUpload = useCallback(() => {
    setShowUploadModal(true);
    setUploadError('');
  }, []);

  const handleDownload = useCallback((fileId: number) => {
    setSelectedFileId(fileId);
    setShowDownloadModal(true);
    setDownloadError('');
  }, []);

  const handleDelete = useCallback((fileId: number) => {
    setSelectedFileId(fileId);
    setShowDeleteModal(true);
    setDeleteError('');
  }, []);

  const handleCloseModals = useCallback(() => {
    setShowUploadModal(false);
    setShowDownloadModal(false);
    setShowDeleteModal(false);
    setSelectedFileId(null);
    setUploadError('');
    setDownloadError('');
    setDeleteError('');
  }, []);

  // Handler para subir archivo
  const handleUploadSubmit = useCallback(async (fileData: UploadFileData, masterPassword: string) => {
    setUploadLoading(true);
    setUploadError('');
    
    try {
      await uploadFile(fileData, masterPassword);
      setSuccessMessage('Archivo subido y encriptado exitosamente');
      setTimeout(() => setSuccessMessage(null), 3000);
      handleCloseModals();
      return { success: true };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Error al subir el archivo';
      setUploadError(errorMessage);
      return { success: false, error: errorMessage };
    } finally {
      setUploadLoading(false);
    }
  }, [uploadFile, handleCloseModals]);

  // Handler para descargar archivo
  const handleDownloadConfirm = useCallback(async (masterPassword: string) => {
    if (!selectedFileId) return;

    setDownloadLoading(true);
    setDownloadError('');
    
    try {
      await downloadFile(selectedFileId, masterPassword);
      setShowDownloadModal(false);
      setSelectedFileId(null);
      setSuccessMessage('Archivo descargado exitosamente');
      setTimeout(() => setSuccessMessage(null), 3000);
    } catch (error) {
      setDownloadError('Contraseña maestra incorrecta o error al descargar');
    } finally {
      setDownloadLoading(false);
    }
  }, [selectedFileId, downloadFile]);

  // Handler para eliminar archivo
  const handleDeleteConfirm = useCallback(async (masterPassword: string) => {
    if (!selectedFileId) return;

    setDeleteLoading(true);
    setDeleteError('');
    
    try {
      await deleteFile(selectedFileId, masterPassword);
      setShowDeleteModal(false);
      setSelectedFileId(null);
      setSuccessMessage('Archivo eliminado exitosamente');
      setTimeout(() => setSuccessMessage(null), 3000);
    } catch (error) {
      setDeleteError('Contraseña maestra incorrecta o error al eliminar');
    } finally {
      setDeleteLoading(false);
    }
  }, [selectedFileId, deleteFile]);

  // Función para cambiar ordenamiento
  const handleSortChange = useCallback((newSortBy: SortBy) => {
    if (sortBy === newSortBy) {
      setSortOrder(prev => prev === 'asc' ? 'desc' : 'asc');
    } else {
      setSortBy(newSortBy);
      setSortOrder('desc');
    }
  }, [sortBy]);

  // Filtrar y ordenar archivos
  const filteredAndSortedFiles = React.useMemo(() => {
    let filtered = files.filter(file =>
      file.title.toLowerCase().includes(searchTerm.toLowerCase())
    );

    filtered.sort((a, b) => {
      let comparison = 0;
      
      switch (sortBy) {
        case 'title':
          comparison = a.title.localeCompare(b.title);
          break;
        case 'uploaded_at':
          comparison = new Date(a.uploaded_at).getTime() - new Date(b.uploaded_at).getTime();
          break;
        case 'algorithm':
          comparison = a.algorithm.localeCompare(b.algorithm);
          break;
      }
      
      return sortOrder === 'asc' ? comparison : -comparison;
    });

    return filtered;
  }, [files, searchTerm, sortBy, sortOrder]);

  const selectedFile = files.find(file => file.id === selectedFileId);

  // Loading state
  if (loading) {
    return (
      <div 
        className="files-loading"
        style={{ backgroundColor: colors.background }}
      >
        <div className="files-loading-content">
          <RefreshCw 
            className="files-loading-spinner animate-spin" 
            style={{ color: colors.primary }} 
          />
          <p style={{ color: colors.textSecondary }}>Cargando archivos...</p>
        </div>
      </div>
    );
  }

  // Error state
  if (error) {
    return (
      <div 
        className="files-loading"
        style={{ backgroundColor: colors.background }}
      >
        <div className="files-loading-content">
          <p style={{ color: colors.error }}>{error}</p>
          <button
            onClick={reloadFiles}
            className="files-retry-button"
            style={{ backgroundColor: colors.primary, marginTop: '1rem' }}
          >
            Reintentar
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="files-page-container" style={{ backgroundColor: colors.background }}>
      {/* Header */}
      <div className="files-header">
        <div className="files-header-content">
          <div className="files-header-info">
            <h1 style={{ color: colors.textPrimary }}>
              Archivos Encriptados
            </h1>
            <p style={{ color: colors.textSecondary }}>
              Gestiona tus archivos de forma segura
            </p>
          </div>
          <button
            className="files-upload-button"
            style={{ backgroundColor: colors.primary }}
            onClick={handleUpload}
          >
            <Upload className="w-5 h-5" />
            Subir Archivo
          </button>
        </div>

        {/* Search and Filter Bar */}
        <div className="files-search-bar">
          <div className="files-search-input-container">
            <Search 
              className="files-search-icon" 
              style={{ color: colors.textMuted }} 
            />
            <input
              type="text"
              placeholder="Buscar archivos..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="files-search-input"
              style={{
                backgroundColor: colors.surface,
                borderColor: colors.border,
                color: colors.textPrimary
              }}
            />
          </div>
          
          {/* Sort Controls */}
          <div className="files-sort-controls">
            <button
              onClick={() => handleSortChange('title')}
              className={`files-sort-button ${sortBy === 'title' ? 'active' : ''}`}
              style={{
                backgroundColor: sortBy === 'title' ? colors.primary : colors.surface,
                borderColor: colors.border,
                color: sortBy === 'title' ? 'white' : colors.textSecondary
              }}
            >
              Nombre
              {sortBy === 'title' && (
                sortOrder === 'asc' ? <SortAsc className="w-4 h-4 ml-1" /> : <SortDesc className="w-4 h-4 ml-1" />
              )}
            </button>
            <button
              onClick={() => handleSortChange('uploaded_at')}
              className={`files-sort-button ${sortBy === 'uploaded_at' ? 'active' : ''}`}
              style={{
                backgroundColor: sortBy === 'uploaded_at' ? colors.primary : colors.surface,
                borderColor: colors.border,
                color: sortBy === 'uploaded_at' ? 'white' : colors.textSecondary
              }}
            >
              Fecha
              {sortBy === 'uploaded_at' && (
                sortOrder === 'asc' ? <SortAsc className="w-4 h-4 ml-1" /> : <SortDesc className="w-4 h-4 ml-1" />
              )}
            </button>
            <button
              onClick={() => handleSortChange('algorithm')}
              className={`files-sort-button ${sortBy === 'algorithm' ? 'active' : ''}`}
              style={{
                backgroundColor: sortBy === 'algorithm' ? colors.primary : colors.surface,
                borderColor: colors.border,
                color: sortBy === 'algorithm' ? 'white' : colors.textSecondary
              }}
            >
              Algoritmo
              {sortBy === 'algorithm' && (
                sortOrder === 'asc' ? <SortAsc className="w-4 h-4 ml-1" /> : <SortDesc className="w-4 h-4 ml-1" />
              )}
            </button>
          </div>
        </div>
      </div>

      {/* Stats */}
      <FileStats files={files} />

      {/* Files Grid */}
      {filteredAndSortedFiles.length > 0 ? (
        <div className="files-grid">
          {filteredAndSortedFiles.map(file => (
            <FileCard
              key={file.id}
              file={file}
              onDownload={handleDownload}
              onDelete={handleDelete}
            />
          ))}
        </div>
      ) : (
        <div className="files-empty-state">
          <Folder 
            className="files-empty-icon" 
            style={{ color: colors.textMuted }} 
          />
          <h3 
            className="files-empty-title"
            style={{ color: colors.textPrimary }}
          >
            No se encontraron archivos
          </h3>
          <p 
            className="files-empty-description"
            style={{ color: colors.textSecondary }}
          >
            {searchTerm 
              ? 'Intenta con otros términos de búsqueda' 
              : 'Sube tu primer archivo para comenzar'
            }
          </p>
          {!searchTerm && (
            <button
              onClick={handleUpload}
              className="files-upload-button mt-4"
              style={{ backgroundColor: colors.primary }}
            >
              <Upload className="w-5 h-5" />
              Subir Primer Archivo
            </button>
          )}
        </div>
      )}

      {/* Modales */}
      <UploadFileModal
        isOpen={showUploadModal}
        onClose={handleCloseModals}
        onSubmit={handleUploadSubmit}
        loading={uploadLoading}
      />

      <DownloadFileModal
        isOpen={showDownloadModal}
        onClose={handleCloseModals}
        onConfirm={handleDownloadConfirm}
        fileName={selectedFile?.title || ''}
        loading={downloadLoading}
        error={downloadError}
      />

      <DeleteFileModal
        isOpen={showDeleteModal}
        onClose={handleCloseModals}
        onConfirm={handleDeleteConfirm}
        fileName={selectedFile?.title || ''}
        loading={deleteLoading}
        error={deleteError}
      />

      {/* Success Message */}
      {successMessage && (
        <div className="fixed bottom-6 right-6 bg-green-500 text-white px-4 py-2 rounded-lg shadow-lg animate-fade-in-out">
          {successMessage}
        </div>
      )}
    </div>
  );
};