// services/fileService.ts — Ficheros zero-knowledge (Fase 2)
//
// El contenido se cifra en el navegador con una FileKey propia (crypto.ts::encryptFile). Esa
// FileKey y los metadatos (nombre, tipo, tamaño) se envuelven con la VaultKey y viajan como
// `ciphertext`. El servidor sólo ve blobs opacos y nunca conoce el nombre real del fichero.
import { cryptoSession, type FileMeta } from './cryptoSession';
import {
  generateFileKey,
  encryptFile,
  decryptFile,
  toBase64,
  fromBase64,
} from './crypto';

import { API_BASE_URL } from '../config/api';

export interface EncryptedFile {
  id: number;
  title: string; // nombre descifrado en cliente
  uploaded_at: string;
  updated_at: string;
  file_path: string;
  size?: number;
  size_formatted?: string;
  contentType?: string;
  error?: string;
}

export interface UploadFileData {
  file: File;
}

export interface ApiResponse {
  success: boolean;
  error?: string;
  errors?: string[];
  message?: string;
}

export interface UploadFileResponse extends ApiResponse {
  file?: { id: number; title: string; uploaded_at: string };
}

export interface DownloadFileResponse {
  success: boolean;
  blob?: Blob;
  filename?: string;
  error?: string;
}

class FileService {
  private getCSRFToken(): string {
    for (const cookie of document.cookie.split(';')) {
      const [name, value] = cookie.trim().split('=');
      if (name === 'csrftoken') return value;
    }
    return '';
  }

  /** Petición JSON estándar (para listar/borrar). La subida/bajada usan fetch directo. */
  private async makeRequest(endpoint: string, options: RequestInit = {}): Promise<any> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
    };
    const csrfToken = this.getCSRFToken();
    if (csrfToken) headers['X-CSRFToken'] = csrfToken;

    const response = await fetch(`${API_BASE_URL}${endpoint}`, {
      ...options,
      headers: { ...headers, ...options.headers },
      credentials: 'include',
    });

    if (!response.ok) {
      if (response.status === 401) {
        window.dispatchEvent(new CustomEvent('auth:sessionExpired'));
        throw new Error('Sesión expirada. Por favor, inicia sesión nuevamente.');
      }
      const errorData = await response.json().catch(() => ({}));
      throw new Error(errorData.error || `Error ${response.status}: ${response.statusText}`);
    }

    return response.json();
  }

  /** Lista de ficheros con el nombre descifrado en cliente. */
  async getFiles(): Promise<EncryptedFile[]> {
    const data = await this.makeRequest('/api/files/');
    const raw: any[] = data.files || [];

    const files: EncryptedFile[] = [];
    for (const f of raw) {
      const base: EncryptedFile = {
        id: f.id,
        title: '(cifrado)',
        uploaded_at: f.uploaded_at,
        updated_at: f.updated_at,
        file_path: f.file_path,
        size: f.size,
        size_formatted: f.size_formatted,
      };
      if (f.ciphertext && f.client_id) {
        try {
          const meta = await cryptoSession.unwrapFileMeta(f.client_id, f.ciphertext, f.crypto_version);
          base.title = meta.filename;
          base.contentType = meta.contentType;
          if (!base.size) base.size = meta.size;
        } catch (error) {
          console.warn(`No se pudo descifrar los metadatos del fichero ${f.id}:`, error);
          base.error = 'No se pudo descifrar';
        }
      }
      files.push(base);
    }
    return files;
  }

  /** Cifra el fichero en cliente y sube el blob opaco + los metadatos envueltos. */
  async uploadFile(fileData: UploadFileData, _masterPassword?: string): Promise<UploadFileResponse> {
    try {
      if (!cryptoSession.isUnlocked()) {
        return { success: false, error: 'La bóveda está bloqueada. Desbloquéala primero.' };
      }

      const file = fileData.file;
      const clientId = cryptoSession.newClientId();

      // 1) Cifrar el contenido con una FileKey aleatoria.
      const fileKey = generateFileKey();
      const encryptedBlob = await encryptFile(fileKey, file);

      // 2) Envolver metadatos + FileKey con la VaultKey.
      const meta: FileMeta = {
        filename: file.name,
        contentType: file.type || 'application/octet-stream',
        size: file.size,
        fileKey: toBase64(fileKey),
      };
      const ciphertext = await cryptoSession.wrapFileMeta(clientId, meta);

      // 3) Subir.
      const formData = new FormData();
      formData.append('file', encryptedBlob, 'blob');
      formData.append('client_id', clientId);
      formData.append('ciphertext', ciphertext);

      const headers: Record<string, string> = {};
      const csrfToken = this.getCSRFToken();
      if (csrfToken) headers['X-CSRFToken'] = csrfToken;

      const response = await fetch(`${API_BASE_URL}/api/files/upload/`, {
        method: 'POST',
        headers, // sin Content-Type: el navegador pone el boundary del multipart
        body: formData,
        credentials: 'include',
      });

      const data = await response.json().catch(() => ({}));
      if (!response.ok) {
        return { success: false, error: data.error || `Error ${response.status}` };
      }
      return { success: data.success, file: data.file, message: data.message };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Error de conexión al subir el archivo',
      };
    }
  }

  /** Descarga el blob cifrado y lo descifra en cliente con la FileKey. */
  async downloadFile(fileId: number, _masterPassword?: string): Promise<DownloadFileResponse> {
    try {
      if (!cryptoSession.isUnlocked()) {
        return { success: false, error: 'La bóveda está bloqueada. Desbloquéala primero.' };
      }

      // Los metadatos (nombre, FileKey) están en la lista; se recuperan de ahí.
      const list = await this.makeRequest('/api/files/');
      const entry = (list.files || []).find((f: any) => f.id === fileId);
      if (!entry || !entry.ciphertext || !entry.client_id) {
        return { success: false, error: 'Archivo no encontrado' };
      }
      const meta = await cryptoSession.unwrapFileMeta(entry.client_id, entry.ciphertext, entry.crypto_version);

      const headers: Record<string, string> = {};
      const csrfToken = this.getCSRFToken();
      if (csrfToken) headers['X-CSRFToken'] = csrfToken;

      const response = await fetch(`${API_BASE_URL}/api/files/${fileId}/download/`, {
        method: 'POST',
        headers,
        credentials: 'include',
      });
      if (!response.ok) {
        const errJson = await response.json().catch(() => ({}));
        return { success: false, error: errJson.error || `Error ${response.status}` };
      }

      const encryptedBlob = await response.blob();
      const plaintext = await decryptFile(fromBase64(meta.fileKey), encryptedBlob);
      const typed = new Blob([plaintext], { type: meta.contentType || 'application/octet-stream' });

      return { success: true, blob: typed, filename: meta.filename };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Error al descargar el archivo',
      };
    }
  }

  async deleteFile(fileId: number, _masterPassword?: string): Promise<ApiResponse> {
    try {
      const data = await this.makeRequest(`/api/files/${fileId}/delete/`, {
        method: 'POST',
        body: JSON.stringify({}),
      });
      return { success: data.success, message: data.message, error: data.error };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Error al eliminar el archivo',
      };
    }
  }

  async deleteAllFiles(_masterPassword?: string): Promise<ApiResponse> {
    try {
      const data = await this.makeRequest('/api/files/delete-all/', {
        method: 'POST',
        body: JSON.stringify({}),
      });
      return { success: data.success, message: data.message, error: data.error, errors: data.errors };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Error al eliminar todos los archivos',
      };
    }
  }

  validateFile(file: File): { valid: boolean; error?: string } {
    const maxSize = 100 * 1024 * 1024; // 100MB
    if (file.size > maxSize) {
      return { valid: false, error: 'El archivo es demasiado grande (máximo 100MB)' };
    }
    if (!file.name || file.name.trim() === '') {
      return { valid: false, error: 'El archivo debe tener un nombre válido' };
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
      pdf: '📄', doc: '📝', docx: '📝', txt: '📄', rtf: '📝',
      xls: '📊', xlsx: '📊', csv: '📊', ppt: '📽️', pptx: '📽️',
      jpg: '🖼️', jpeg: '🖼️', png: '🖼️', gif: '🖼️', svg: '🖼️', webp: '🖼️',
      mp3: '🎵', wav: '🎵', m4a: '🎵', mp4: '🎥', avi: '🎥', mov: '🎥', webm: '🎥',
      zip: '🗜️', rar: '🗜️', '7z': '🗜️', tar: '🗜️', gz: '🗜️',
      js: '💻', ts: '💻', py: '💻', java: '💻', cpp: '💻', html: '💻', css: '💻', json: '💻', xml: '💻',
    };
    return iconMap[extension] || '📎';
  }
}

export const fileService = new FileService();
