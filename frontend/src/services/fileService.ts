// services/fileService.ts - Corregido para MinIO
const API_BASE_URL = 'http://localhost:8000';

export interface EncryptedFile {
  id: number;
  title: string;
  algorithm: string;
  uploaded_at: string;
  updated_at: string;
  encrypted_key: string;
  salt: string;
  iv_or_nonce: string;
  file_path: string;
  // Campos de MinIO
  size?: number;
  size_formatted?: string;
  minio_last_modified?: string;
  etag?: string;
  encryption_metadata?: Record<string, any>;
  minio_error?: string;
}

export interface UploadFileData {
  file: File;
  algorithm: string;
}

export interface ApiResponse {
  success: boolean;
  error?: string;
  errors?: string[];
  message?: string;
}

export interface UploadFileResponse extends ApiResponse {
  file?: {
    id: number;
    title: string;
    algorithm: string;
    uploaded_at: string;
  };
}

export interface DownloadFileResponse {
  success: boolean;
  blob?: Blob;
  filename?: string;
  error?: string;
}

export interface FileStatsResponse {
  success: boolean;
  stats?: {
    total_files: number;
    total_size: number;
    total_size_formatted: string;
    algorithms_used: string[];
    recent_uploads: number;
    minio_sync_success: number;
    algorithm_distribution: Record<string, number>;
  };
  error?: string;
}

class FileService {
  private async getCSRFToken(): Promise<string> {
    const cookies = document.cookie.split(';');
    for (let cookie of cookies) {
      const [name, value] = cookie.trim().split('=');
      if (name === 'csrftoken') {
        return value;
      }
    }
    
    const csrfMeta = document.querySelector('meta[name="csrf-token"]') as HTMLMetaElement;
    if (csrfMeta) {
      return csrfMeta.content;
    }

    try {
      await fetch(`${API_BASE_URL}/`, {
        method: 'GET',
        credentials: 'include',
      });
      
      const newCookies = document.cookie.split(';');
      for (let cookie of newCookies) {
        const [name, value] = cookie.trim().split('=');
        if (name === 'csrftoken') {
          return value;
        }
      }
    } catch (error) {
      console.warn('No se pudo obtener el token CSRF:', error);
    }
    
    return '';
  }

  private async makeRequest(
    endpoint: string,
    options: RequestInit = {}
  ): Promise<any> {
    try {
      const csrfToken = await this.getCSRFToken();
      
      const headers: Record<string, string> = {
        'X-CSRFToken': csrfToken,
        'Accept': 'application/json',
      };

      if (options.headers) {
        const additionalHeaders = options.headers as Record<string, string>;
        Object.assign(headers, additionalHeaders);
      }

      if (!(options.body instanceof FormData)) {
        headers['Content-Type'] = 'application/json';
      }

      const response = await fetch(`${API_BASE_URL}${endpoint}`, {
        ...options,
        headers,
        credentials: 'include',
      });

      // Para descargas de archivos, retornar la respuesta directamente
      if (endpoint.includes('/download/') && response.ok) {
        return response;
      }

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        throw new Error(errorData.error || `Error ${response.status}: ${response.statusText}`);
      }

      return await response.json();
    } catch (error) {
      console.error('File Service Error:', error);
      throw error;
    }
  }

  async getFiles(): Promise<EncryptedFile[]> {
    try {
      const data = await this.makeRequest('/api/files/');
      return data.files || [];
    } catch (error) {
      console.error('Error fetching files:', error);
      throw new Error('Error al cargar los archivos');
    }
  }

  async uploadFile(fileData: UploadFileData, masterPassword: string): Promise<UploadFileResponse> {
    try {
      if (!masterPassword.trim()) {
        throw new Error('Master password requerida');
      }

      const formData = new FormData();
      formData.append('file', fileData.file);
      formData.append('algorithm', fileData.algorithm);
      formData.append('master_password', masterPassword);

      const data = await this.makeRequest('/api/files/upload/', {
        method: 'POST',
        body: formData
      });

      return {
        success: data.success,
        file: data.file,
        message: data.message || 'Archivo subido exitosamente'
      };
    } catch (error) {
      console.error('Error uploading file:', error);
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Error de conexión al subir el archivo'
      };
    }
  }

  async downloadFile(fileId: number, masterPassword: string): Promise<DownloadFileResponse> {
  try {
    if (!masterPassword.trim()) {
      throw new Error('Master password requerida');
    }

    const response = await this.makeRequest(`/api/files/${fileId}/download/`, {
      method: 'POST',
      body: JSON.stringify({
        master_password: masterPassword
      })
    }) as Response;

    // Verificar que la respuesta es exitosa
    if (!response.ok) {
      const errorText = await response.text();
      let errorMessage = 'Error al descargar el archivo';
      
      try {
        const errorJson = JSON.parse(errorText);
        errorMessage = errorJson.error || errorMessage;
      } catch {
        errorMessage = `Error ${response.status}: ${response.statusText}`;
      }
      
      throw new Error(errorMessage);
    }

    // Añadir este código justo después de verificar response.ok
    console.log('=== DEBUG HEADERS ===');
    console.log('Response status:', response.status);
    console.log('Response headers:');
    for (let [key, value] of response.headers.entries()) {
      console.log(`  ${key}: ${value}`);
    }
    console.log('Content-Disposition específico:', response.headers.get('Content-Disposition'));
    console.log('Content-Type específico:', response.headers.get('Content-Type'));
    console.log('=== FIN DEBUG ===');

    const blob = await response.blob();
    const contentDisposition = response.headers.get('Content-Disposition');
    let filename = 'download';
    
    // CORRECCIÓN: Mejorar completamente el parsing del Content-Disposition
    if (contentDisposition) {
      console.log('Content-Disposition header:', contentDisposition);
      
      // Método 1: Buscar filename*=UTF-8''... (RFC 6266)
      const utf8Match = contentDisposition.match(/filename\*\s*=\s*UTF-8''([^;,\s]+)/i);
      if (utf8Match && utf8Match[1]) {
        try {
          filename = decodeURIComponent(utf8Match[1]);
          console.log('Filename extraído con UTF-8:', filename);
        } catch (e) {
          console.warn('Error decodificando filename UTF-8:', e);
        }
      } else {
        // Método 2: Buscar filename="..." (con comillas)
        const quotedMatch = contentDisposition.match(/filename\s*=\s*"([^"]+)"/i);
        if (quotedMatch && quotedMatch[1]) {
          filename = quotedMatch[1];
          console.log('Filename extraído con comillas:', filename);
        } else {
          // Método 3: Buscar filename=... (sin comillas)
          const unquotedMatch = contentDisposition.match(/filename\s*=\s*([^;,\s]+)/i);
          if (unquotedMatch && unquotedMatch[1]) {
            filename = unquotedMatch[1];
            console.log('Filename extraído sin comillas:', filename);
          }
        }
      }
    }

    // Asegurar que el filename no esté vacío
    if (!filename || filename.trim() === '' || filename === 'undefined') {
      filename = 'archivo_descargado';
      console.log('Usando filename por defecto:', filename);
    }

    console.log('Archivo descargado:', {
      filename,
      size: blob.size,
      type: blob.type,
      contentDisposition
    });

    return {
      success: true,
      blob,
      filename: filename.trim()
    };
  } catch (error) {
    console.error('Error downloading file:', error);
    return {
      success: false,
      error: error instanceof Error ? error.message : 'Error al descargar el archivo'
    };
  }
}

  async deleteFile(fileId: number, masterPassword: string): Promise<ApiResponse> {
    try {
      if (!masterPassword.trim()) {
        throw new Error('Master password requerida');
      }

      const data = await this.makeRequest(`/api/files/${fileId}/delete/`, {
        method: 'POST',
        body: JSON.stringify({
          master_password: masterPassword
        })
      });

      return {
        success: data.success,
        message: data.message,
        error: data.error
      };
    } catch (error) {
      console.error('Error deleting file:', error);
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Error al eliminar el archivo'
      };
    }
  }

  async deleteAllFiles(masterPassword: string): Promise<ApiResponse> {
    try {
      if (!masterPassword.trim()) {
        throw new Error('Master password requerida');
      }

      const data = await this.makeRequest('/api/files/delete-all/', {
        method: 'POST',
        body: JSON.stringify({
          master_password: masterPassword
        })
      });

      return {
        success: data.success,
        message: data.message,
        error: data.error,
        errors: data.errors
      };
    } catch (error) {
      console.error('Error deleting all files:', error);
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Error al eliminar todos los archivos'
      };
    }
  }

  async getFileStats(): Promise<FileStatsResponse> {
    try {
      const data = await this.makeRequest('/api/files/stats/');
      return {
        success: true,
        stats: data.stats
      };
    } catch (error) {
      console.error('Error fetching file stats:', error);
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Error al cargar estadísticas'
      };
    }
  }

  validateFile(file: File): { valid: boolean; error?: string } {
    const maxSize = 100 * 1024 * 1024; // 100MB
    if (file.size > maxSize) {
      return {
        valid: false,
        error: 'El archivo es demasiado grande (máximo 100MB)'
      };
    }

    if (!file.name || file.name.trim() === '') {
      return {
        valid: false,
        error: 'El archivo debe tener un nombre válido'
      };
    }

    const dangerousChars = /[<>:"/\\|?*\x00-\x1f]/;
    if (dangerousChars.test(file.name)) {
      return {
        valid: false,
        error: 'El nombre del archivo contiene caracteres no válidos'
      };
    }

    return { valid: true };
  }

  formatFileSize(bytes: number): string {
    if (bytes === 0) return '0 B';
    
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    
    return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`;
  }

  getFileExtension(filename: string): string {
    return filename.slice((filename.lastIndexOf('.') - 1 >>> 0) + 2);
  }

  getFileIcon(filename: string): string {
    const extension = this.getFileExtension(filename).toLowerCase();
    
    const iconMap: Record<string, string> = {
      // Documentos
      pdf: '📄',
      doc: '📝',
      docx: '📝',
      txt: '📄',
      rtf: '📝',
      // Hojas de cálculo
      xls: '📊',
      xlsx: '📊',
      csv: '📊',
      // Presentaciones
      ppt: '📽️',
      pptx: '📽️',
      // Imágenes
      jpg: '🖼️',
      jpeg: '🖼️',
      png: '🖼️',
      gif: '🖼️',
      svg: '🖼️',
      webp: '🖼️',
      // Audio
      mp3: '🎵',
      wav: '🎵',
      m4a: '🎵',
      // Video
      mp4: '🎥',
      avi: '🎥',
      mov: '🎥',
      webm: '🎥',
      // Archivos comprimidos
      zip: '🗜️',
      rar: '🗜️',
      '7z': '🗜️',
      tar: '🗜️',
      gz: '🗜️',
      // Código
      js: '💻',
      ts: '💻',
      py: '💻',
      java: '💻',
      cpp: '💻',
      html: '💻',
      css: '💻',
      json: '💻',
      xml: '💻'
    };
    
    return iconMap[extension] || '📎';
  }
}

export const fileService = new FileService();