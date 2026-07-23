// services/authService.ts - Autenticación por cookies HttpOnly (paso 8, A1/A2)
//
// Antes esta clase guardaba el access y el refresh (7 días) en localStorage Y
// sessionStorage, ambos legibles desde JavaScript: cualquier XSS se llevaba la
// sesión entera durante una semana. Ahora los tokens viven en cookies HttpOnly
// que el servidor emite y el navegador custodia; este código NO puede leerlos
// —ni falta que hace— y se limita a:
//
//   - mandar todas las peticiones con `credentials: 'include'` para que el
//     navegador adjunte las cookies,
//   - añadir la cabecera `X-CSRFToken` (doble envío) en las mutaciones,
//   - reaccionar a un 401 pidiendo una renovación y reintentando una vez.
//
// El estado de sesión ya no se puede deducir de un token en memoria (no lo hay);
// se mantiene un booleano `authenticated` que se pone a true tras un login o un
// checkAuthStatus con éxito y a false al cerrar sesión o ante un 401 no
// recuperable. La fuente de verdad sigue siendo el servidor: la cookie de
// sesión es HttpOnly y sólo él sabe si es válida.

import { API_BASE_URL } from '../config/api';

export interface AuthUser {
  id: number;
  username: string;
  email: string;
  firstName: string;
  lastName: string;
  isAuthenticated: boolean;
  hasMasterKey: boolean;
}

export interface LoginCredentials {
  email: string;
  password: string;
}

export interface RegisterData {
  firstName: string;
  lastName: string;
  email: string;
  password: string;
}

export interface AuthResponse {
  success: boolean;
  error?: string;
  user?: AuthUser;
}

class SecureAuthService {
  private baseURL = API_BASE_URL;
  private authenticated = false;
  private isRefreshing = false;
  private refreshPromise: Promise<void> | null = null;
  private userKey = 'user_data';

  // ===========================================
  // GESTIÓN DE CSRF
  // ===========================================
  //
  // El valor CSRF viaja en una cookie NO HttpOnly (a propósito: el doble envío
  // exige que el JS la lea) que hay que copiar en la cabecera X-CSRFToken. Un
  // sitio de terceros no puede leer esa cookie (misma política de origen), que
  // es justo lo que hace inútil un CSRF.

  private readCSRFCookie(): string {
    for (const cookie of document.cookie.split(';')) {
      const [name, value] = cookie.trim().split('=');
      if (name === 'csrftoken') {
        return value;
      }
    }
    return '';
  }

  private async getCSRFToken(): Promise<string> {
    const fromCookie = this.readCSRFCookie();
    if (fromCookie) {
      return fromCookie;
    }

    // Si aún no existe (primer contacto), pedirla. `ensure_csrf_cookie` en el
    // backend la deja escrita en la respuesta.
    try {
      const response = await fetch(`${this.baseURL}/api/csrf/`, {
        method: 'GET',
        credentials: 'include',
      });
      if (response.ok) {
        const data = await response.json().catch(() => null);
        if (data?.csrfToken) {
          return data.csrfToken;
        }
      }
    } catch (error) {
      console.warn('No se pudo obtener token CSRF:', error);
    }

    return this.readCSRFCookie();
  }

  private async getAuthHeaders(): Promise<Record<string, string>> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
    };

    // Ya no se añade `Authorization`: el access token va en la cookie HttpOnly
    // que el navegador adjunta solo. Sólo hace falta el CSRF del doble envío.
    const csrfToken = await this.getCSRFToken();
    if (csrfToken) {
      headers['X-CSRFToken'] = csrfToken;
    }

    return headers;
  }

  // ===========================================
  // RENOVACIÓN DE TOKEN
  // ===========================================
  //
  // No se puede programar por adelantado: el `exp` del access está dentro de una
  // cookie que este código no puede leer. En su lugar, la renovación es reactiva
  // —un 401 la dispara— y protegida contra estampidas con un promise compartido.

  private async refreshAccessToken(): Promise<void> {
    if (this.isRefreshing && this.refreshPromise) {
      return this.refreshPromise;
    }

    this.isRefreshing = true;
    this.refreshPromise = this.performTokenRefresh();

    try {
      await this.refreshPromise;
    } finally {
      this.isRefreshing = false;
      this.refreshPromise = null;
    }
  }

  private async performTokenRefresh(): Promise<void> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
    };
    const csrfToken = await this.getCSRFToken();
    if (csrfToken) {
      headers['X-CSRFToken'] = csrfToken;
    }

    // Sin cuerpo: el refresh viaja en la cookie HttpOnly. El backend
    // (CookieTokenRefreshView) lo lee de ahí y reescribe las cookies.
    const response = await fetch(`${this.baseURL}/api/token/refresh/`, {
      method: 'POST',
      headers,
      credentials: 'include',
    });

    if (!response.ok) {
      throw new Error(`Token refresh failed: ${response.status}`);
    }
  }

  // ===========================================
  // PETICIONES AUTENTICADAS
  // ===========================================

  private async handleResponse<T>(response: Response): Promise<T> {
    let data: any;
    try {
      data = await response.json();
    } catch {
      throw new Error('Respuesta del servidor inválida');
    }

    if (!response.ok) {
      if (response.status === 401) {
        // Puede ser un access caducado: se señaliza para que makeSecureRequest
        // intente renovar y reintentar una vez.
        throw new Error('UNAUTHORIZED');
      }

      if (data && typeof data === 'object' && 'success' in data) {
        return data as T;
      }

      const errorMessages: Record<number, string> = {
        400: 'Datos inválidos',
        403: 'Acceso denegado',
        404: 'No encontrado',
        429: 'Demasiados intentos',
        500: 'Error del servidor',
      };
      throw new Error(errorMessages[response.status] || 'Error inesperado');
    }

    return data;
  }

  private async makeSecureRequest<T>(
    endpoint: string,
    options: RequestInit = {},
    retryCount: number = 0
  ): Promise<T> {
    try {
      const headers = await this.getAuthHeaders();
      const response = await fetch(`${this.baseURL}${endpoint}`, {
        ...options,
        headers: { ...headers, ...options.headers },
        credentials: 'include',
      });
      return await this.handleResponse<T>(response);
    } catch (error) {
      if (error instanceof Error && error.message === 'UNAUTHORIZED') {
        if (retryCount < 1) {
          // Un único intento de renovar y reintentar. Si la renovación falla,
          // la sesión se da por terminada.
          try {
            await this.refreshAccessToken();
          } catch {
            this.handleAuthError();
            throw new Error('Sesión expirada. Por favor, inicia sesión nuevamente.');
          }
          return this.makeSecureRequest<T>(endpoint, options, retryCount + 1);
        }
        this.handleAuthError();
        throw new Error('Sesión expirada. Por favor, inicia sesión nuevamente.');
      }
      throw error;
    }
  }

  private handleAuthError(): void {
    // No se dispara 'auth:sessionExpired' aquí a propósito. En la carga inicial
    // sin sesión previa, checkAuthStatus recibe un 401 legítimo y emitir el
    // evento marcaría "sesión expirada" en una primera visita. La expiración
    // real (había usuario y dejó de haberlo) la detecta AuthProvider por su
    // propio estado, y un 401 en mitad del uso lo señalan los 9 servicios desde
    // su propio manejador.
    this.authenticated = false;
    this.clearUserData();
  }

  private storeUserData(user: AuthUser): void {
    try {
      localStorage.setItem(this.userKey, JSON.stringify(user));
    } catch (error) {
      console.warn('Error guardando datos de usuario:', error);
    }
  }

  private clearUserData(): void {
    try {
      localStorage.removeItem(this.userKey);
      sessionStorage.removeItem(this.userKey);
    } catch (error) {
      console.warn('Error limpiando datos de usuario:', error);
    }
  }

  // ===========================================
  // MÉTODOS PÚBLICOS
  // ===========================================

  async checkAuthStatus(): Promise<AuthResponse> {
    try {
      // Sin precomprobación de token: la cookie se adjunta sola y si el access
      // ha caducado, makeSecureRequest renueva de forma transparente.
      const data = await this.makeSecureRequest<any>('/auth/check/');

      if (data.success && data.user) {
        this.authenticated = true;
        this.storeUserData(data.user);
        return { success: true, user: data.user };
      }

      this.authenticated = false;
      return { success: false };
    } catch (error) {
      console.error('Error checking auth status:', error);
      this.authenticated = false;
      return { success: false };
    }
  }

  async login(credentials: LoginCredentials): Promise<AuthResponse> {
    try {
      const validation = this.validateLoginCredentials(credentials);
      if (!validation.valid) {
        return { success: false, error: validation.error };
      }

      const data = await this.makeSecureRequest<any>('/auth/login/', {
        method: 'POST',
        body: JSON.stringify({
          email: credentials.email.trim().toLowerCase(),
          password: credentials.password,
        }),
      });

      if (data.success && data.user) {
        this.authenticated = true;
        this.storeUserData(data.user);
        return { success: true, user: data.user };
      }

      return { success: false, error: data.error || 'Credenciales incorrectas' };
    } catch (error) {
      console.error('Error en login:', error);
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Error de conexión',
      };
    }
  }

  async register(userData: RegisterData): Promise<AuthResponse> {
    try {
      const validation = this.validateRegistrationData(userData);
      if (!validation.valid) {
        return { success: false, error: validation.error };
      }

      const data = await this.makeSecureRequest<any>('/auth/register/', {
        method: 'POST',
        body: JSON.stringify({
          first_name: userData.firstName.trim(),
          last_name: userData.lastName.trim(),
          email: userData.email.trim().toLowerCase(),
          password: userData.password,
        }),
      });

      if (data.success && data.user) {
        this.authenticated = true;
        this.storeUserData(data.user);
        return { success: true, user: data.user };
      }

      return { success: false, error: data.error || 'Error en el registro' };
    } catch (error) {
      console.error('Error en register:', error);
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Error de conexión',
      };
    }
  }

  async logout(): Promise<{ success: boolean; error?: string }> {
    try {
      // POST sin cuerpo: el backend lee el refresh de la cookie, invalida ese
      // (sólo este dispositivo) y borra ambas cookies.
      await this.makeSecureRequest('/auth/logout/', { method: 'POST' });
    } catch (error) {
      console.warn('Error en logout del servidor:', error);
    } finally {
      this.authenticated = false;
      this.clearUserData();
      window.dispatchEvent(new CustomEvent('auth:logout'));
    }
    return { success: true };
  }

  // ===========================================
  // MÉTODOS UTILITARIOS
  // ===========================================

  isAuthenticated(): boolean {
    return this.authenticated;
  }

  getCurrentUser(): AuthUser | null {
    try {
      const userData = localStorage.getItem(this.userKey);
      return userData ? JSON.parse(userData) : null;
    } catch (error) {
      console.error('Error obteniendo usuario actual:', error);
      return null;
    }
  }

  // Conservado por compatibilidad con los 9 servicios, que hacen
  // `if (token) headers['Authorization'] = ...`. Con las cookies HttpOnly ya no
  // hay token accesible desde JS, así que devuelve null y esos servicios se
  // apoyan en la cookie + `credentials: 'include'`, sin cabecera Authorization.
  getAccessToken(): string | null {
    return null;
  }

  async authenticatedRequest<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
    return this.makeSecureRequest<T>(endpoint, options);
  }

  async healthCheck(): Promise<boolean> {
    try {
      const response = await fetch(`${this.baseURL}/health/`, {
        method: 'GET',
        credentials: 'include',
      });
      return response.ok;
    } catch {
      return false;
    }
  }

  // ===========================================
  // VALIDACIONES
  // ===========================================

  private validateLoginCredentials(credentials: LoginCredentials): { valid: boolean; error?: string } {
    if (!credentials.email?.trim()) {
      return { valid: false, error: 'El email es requerido' };
    }
    if (!credentials.password) {
      return { valid: false, error: 'La contraseña es requerida' };
    }
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(credentials.email.trim())) {
      return { valid: false, error: 'Formato de email inválido' };
    }
    return { valid: true };
  }

  private validateRegistrationData(userData: RegisterData): { valid: boolean; error?: string } {
    if (!userData.firstName?.trim() || !userData.lastName?.trim()) {
      return { valid: false, error: 'Nombre y apellido son requeridos' };
    }
    if (!userData.email?.trim()) {
      return { valid: false, error: 'El email es requerido' };
    }
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(userData.email.trim())) {
      return { valid: false, error: 'Formato de email inválido' };
    }
    const passwordValidation = this.validatePassword(userData.password);
    if (!passwordValidation.valid) {
      return passwordValidation;
    }
    return { valid: true };
  }

  private validatePassword(password: string): { valid: boolean; error?: string } {
    if (!password) {
      return { valid: false, error: 'La contraseña es requerida' };
    }
    if (password.length < 12) {
      return { valid: false, error: 'La contraseña debe tener al menos 12 caracteres' };
    }
    return { valid: true };
  }
}

export const authService = new SecureAuthService();
export default authService;
