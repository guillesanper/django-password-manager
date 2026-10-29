// hooks/useFiles.ts - Corregido para MinIO
import { useState, useEffect, useCallback } from 'react';
import { fileService, type EncryptedFile, type UploadFileData } from '../../services/fileService';

interface UseFilesReturn {
  files: EncryptedFile[];
  loading: boolean;
  error: string | null;
  uploadFile: (fileData: UploadFileData) => Promise<{ success: boolean; message?: string }>;
  downloadFile: (fileId: number) => Promise<{ success: boolean }>;
  deleteFile: (fileId: number) => Promise<{ success: boolean; message?: string }>;
  deleteAllFiles: () => Promise<{ success: boolean; message?: string; errors?: string[] }>;
  reloadFiles: () => Promise<void>;
  validateFile: (file: File) => { valid: boolean; error?: string };
  formatFileSize: (bytes: number) => string;
  getFileIcon: (filename: string) => string;
}

export const useFiles = (): UseFilesReturn => {
  const [files, setFiles] = useState<EncryptedFile[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const loadFiles = useCallback(async () => {
    setLoading(true);
    setError(null);
    
    try {
      const filesData = await fileService.getFiles();
      setFiles(filesData);
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Error al cargar los archivos';
      setError(errorMessage);
      console.error('Error loading files:', err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadFiles();
  }, [loadFiles]);

  const uploadFile = useCallback(async (fileData: UploadFileData) => {
    try {
      // Validar archivo antes de subir
      const validation = fileService.validateFile(fileData.file);
      if (!validation.valid) {
        throw new Error(validation.error);
      }

      const result = await fileService.uploadFile(fileData);
      
      if (result.success && result.file) {
        // Recargar la lista de archivos para obtener la información completa desde el servidor
        await loadFiles();
        return { success: true, message: result.message };
      } else {
        throw new Error(result.error || 'Error al subir el archivo');
      }
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Error al subir el archivo';
      console.error('Error uploading file:', err);
      throw new Error(errorMessage);
    }
  }, [loadFiles]);

  const downloadFile = useCallback(async (fileId: number) => {
    try {
      const result = await fileService.downloadFile(fileId);
      
      if (result.success && result.blob && result.filename) {
        // Crear URL del blob y disparar descarga
        const url = window.URL.createObjectURL(result.blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = result.filename;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        window.URL.revokeObjectURL(url);
        
        return { success: true };
      } else {
        throw new Error(result.error || 'Error al descargar el archivo');
      }
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Error al descargar el archivo';
      console.error('Error downloading file:', err);
      throw new Error(errorMessage);
    }
  }, []);

  const deleteFile = useCallback(async (fileId: number) => {
    try {
      const result = await fileService.deleteFile(fileId);
      
      if (result.success) {
        // Eliminar el archivo del estado local
        setFiles(prev => prev.filter(file => file.id !== fileId));
        return { success: true, message: result.message };
      } else {
        throw new Error(result.error || 'Error al eliminar el archivo');
      }
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Error al eliminar el archivo';
      console.error('Error deleting file:', err);
      throw new Error(errorMessage);
    }
  }, []);

  const deleteAllFiles = useCallback(async () => {
    try {
      const result = await fileService.deleteAllFiles();
      
      if (result.success) {
        // Limpiar el estado local
        setFiles([]);
        return { 
          success: true, 
          message: result.message,
          errors: result.errors 
        };
      } else {
        // Si hay errores parciales, recargar la lista para reflejar el estado real
        if (result.errors && result.errors.length > 0) {
          await loadFiles();
          return {
            success: false,
            message: result.message,
            errors: result.errors
          };
        }
        
        throw new Error(result.error || 'Error al eliminar todos los archivos');
      }
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Error al eliminar todos los archivos';
      console.error('Error deleting all files:', err);
      throw new Error(errorMessage);
    }
  }, [loadFiles]);

  // Funciones auxiliares que delegan al servicio
  const validateFile = useCallback((file: File) => {
    return fileService.validateFile(file);
  }, []);

  const formatFileSize = useCallback((bytes: number) => {
    return fileService.formatFileSize(bytes);
  }, []);

  const getFileIcon = useCallback((filename: string) => {
    return fileService.getFileIcon(filename);
  }, []);

  return {
    files,
    loading,
    error,
    uploadFile,
    downloadFile,
    deleteFile,
    deleteAllFiles,
    reloadFiles: loadFiles,
    validateFile,
    formatFileSize,
    getFileIcon
  };
};