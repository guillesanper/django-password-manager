// services/authService.ts - Servicio completo de autenticación con JWT y seguridad reforzada

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
  tokens?: {
    access: string;
    refresh: string;
  };
}

export interface JWTTokens {
  access: string;
  refresh: string;
  expiresAt?: number;
}

class SecureAuthService {
  private baseURL = import.meta.env.VITE_API_URL || 'http://localhost:8000';
  private accessToken: string | null = null;
  private refreshToken: string | null = null;
  private tokenExpiryTime: number | null = null;
  private refreshTimer: NodeJS.Timeout | null = null;

  constructor() {
    this.loadTokensFromStorage();
    this.setupAutomaticTokenRefresh();
  }

  // ===========================================
  // GESTIÓN SEGURA DE TOKENS JWT
  // ===========================================

  private saveTokensToStorage(tokens: JWTTokens): void {
    try {
      const tokenData = {
        access: tokens.access,
        refresh: tokens.refresh,
        expiresAt: tokens.expiresAt || this.calculateTokenExpiry(tokens.access),
        timestamp: Date.now()
      };

      sessionStorage.setItem('auth_tokens', JSON.stringify(tokenData));
      this.accessToken = tokens.access;
      this.refreshToken = tokens.refresh;
      this.tokenExpiryTime = tokenData.expiresAt;
    } catch (error) {
      console.error('Error saving tokens:', error);
    }
  }

  private loadTokensFromStorage(): void {
    try {
      const stored = sessionStorage.getItem('auth_tokens');
      if (stored) {
        const tokenData = JSON.parse(stored);
        const now = Date.now();
        
        if (tokenData.expiresAt && now < tokenData.expiresAt) {
          this.accessToken = tokenData.access;
          this.refreshToken = tokenData.refresh;
          this.tokenExpiryTime = tokenData.expiresAt;
        } else {
          this.clearTokens();
        }
      }
    } catch (error) {
      console.error('Error loading tokens:', error);
      this.clearTokens();
    }
  }

  private clearTokens(): void {
    this.accessToken = null;
    this.refreshToken = null;
    this.tokenExpiryTime = null;
    
    try {
      sessionStorage.removeItem('auth_tokens');
      sessionStorage.removeItem('user_data');
    } catch (error) {
      console.error('Error clearing tokens:', error);
    }

    if (this.refreshTimer) {
      clearTimeout(this.refreshTimer);
      this.refreshTimer = null;
    }
  }

  private calculateTokenExpiry(accessToken: string): number {
    try {
      const payload = JSON.parse(atob(accessToken.split('.')[1]));
      return payload.exp * 1000;
    } catch (error) {
      return Date.now() + (15 * 60 * 1000);
    }
  }

  private setupAutomaticTokenRefresh(): void {
    const scheduleRefresh = () => {
      if (this.refreshTimer) {
        clearTimeout(this.refreshTimer);
      }

      if (this.tokenExpiryTime && this.refreshToken) {
        const refreshTime = this.tokenExpiryTime - Date.now() - (2 * 60 * 1000);
        
        if (refreshTime > 0) {
          this.refreshTimer = setTimeout(async () => {
            console.log('Renovando token automáticamente...');
            await this.refreshAccessToken();
            scheduleRefresh();
          }, refreshTime);
        }
      }
    };

    scheduleRefresh();
  }

  // ===========================================
  // GESTIÓN DE CSRF TOKENS
  // ===========================================

  private async getCSRFToken(): Promise<string> {
    const cookies = document.cookie.split(';');
    for (let cookie of cookies) {
      const [name, value] = cookie.trim().split('=');
      if (name === 'csrftoken') {
        return value;
      }
    }

    try {
      const response = await fetch(`${this.baseURL}/admin/`, {
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
      console.warn('No se pudo obtener token CSRF:', error);
    }

    throw new Error('No se pudo obtener token CSRF');
  }

  private async getAuthHeaders(): Promise<Record<string, string>> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
    };

    try {
      const csrfToken = await this.getCSRFToken();
      headers['X-CSRFToken'] = csrfToken;
    } catch (error) {
      console.warn('CSRF token no disponible:', error);
    }

    if (this.accessToken) {
      headers['Authorization'] = `Bearer ${this.accessToken}`;
    }

    return headers;
  }

  // ===========================================
  // MANEJO DE RESPUESTAS HTTP
  // ===========================================

  private async handleResponse<T>(response: Response): Promise<T> {
    let data;
    
    try {
      data = await response.json();
    } catch (error) {
      throw new Error('Error del servidor. Respuesta inválida.');
    }

    if (!response.ok) {
      if (response.status === 401 && this.refreshToken) {
        console.log('Token expirado, intentando renovar...');
        try {
          await this.refreshAccessToken();
          throw new Error('TOKEN_REFRESHED');
        } catch (refreshError) {
          console.error('Error renovando token:', refreshError);
          this.handleAuthError();
          throw new Error('Sesión expirada. Por favor, inicia sesión nuevamente.');
        }
      }

      if (data?.error) {
        throw new Error(data.error);
      }

      const errorMessages: Record<number, string> = {
        400: 'Datos inválidos. Verifica la información ingresada.',
        401: 'Credenciales incorrectas o sesión expirada.',
        403: 'No tienes permisos para realizar esta acción.',
        404: 'Recurso no encontrado.',
        429: 'Demasiados intentos. Espera un momento.',
        500: 'Error interno del servidor. Intenta más tarde.',
      };

      throw new Error(errorMessages[response.status] || 'Error inesperado. Intenta nuevamente.');
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
      if (error instanceof Error && error.message === 'TOKEN_REFRESHED' && retryCount < 1) {
        return this.makeSecureRequest<T>(endpoint, options, retryCount + 1);
      }
      throw error;
    }
  }

  // ===========================================
  // GESTIÓN DE TOKENS JWT
  // ===========================================

  private async refreshAccessToken(): Promise<void> {
    if (!this.refreshToken) {
      throw new Error('No refresh token available');
    }

    try {
      const response = await fetch(`${this.baseURL}/api/token/refresh/`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        credentials: 'include',
        body: JSON.stringify({
          refresh: this.refreshToken
        })
      });

      if (!response.ok) {
        throw new Error('Token refresh failed');
      }

      const data = await response.json();
      
      if (data.access) {
        const newTokens: JWTTokens = {
          access: data.access,
          refresh: data.refresh || this.refreshToken,
        };

        this.saveTokensToStorage(newTokens);
        console.log('Token renovado exitosamente');
      } else {
        throw new Error('Invalid refresh response');
      }
    } catch (error) {
      console.error('Error refreshing token:', error);
      this.handleAuthError();
      throw error;
    }
  }

  private handleAuthError(): void {
    this.clearTokens();
    window.dispatchEvent(new CustomEvent('auth:sessionExpired'));
    
    if (window.location.pathname !== '/login') {
      window.location.href = '/login?expired=true';
    }
  }

  // ===========================================
  // MÉTODOS PÚBLICOS DE AUTENTICACIÓN
  // ===========================================

  async checkAuthStatus(): Promise<AuthResponse> {
    try {
      const data = await this.makeSecureRequest<any>('/auth/check/');
      
      return {
        success: data.isAuthenticated,
        user: data.isAuthenticated ? data.user : null
      };
    } catch (error) {
      console.error('Error checking auth status:', error);
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Error de conexión'
      };
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
          password: credentials.password
        })
      });

      if (data.success && data.user && data.tokens) {
        this.saveTokensToStorage(data.tokens);
        
        try {
          sessionStorage.setItem('user_data', JSON.stringify(data.user));
        } catch (error) {
          console.warn('Error saving user data:', error);
        }

        this.setupAutomaticTokenRefresh();

        console.log('Login exitoso');
        return {
          success: true,
          user: data.user,
          tokens: data.tokens
        };
      } else {
        return {
          success: false,
          error: data.error || 'Credenciales incorrectas'
        };
      }
    } catch (error) {
      console.error('Error in login:', error);
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Error de conexión'
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
          password: userData.password
        })
      });

      if (data.success && data.user && data.tokens) {
        this.saveTokensToStorage(data.tokens);
        
        try {
          sessionStorage.setItem('user_data', JSON.stringify(data.user));
        } catch (error) {
          console.warn('Error saving user data:', error);
        }

        this.setupAutomaticTokenRefresh();

        console.log('Registro exitoso');
        return {
          success: true,
          user: data.user,
          tokens: data.tokens
        };
      } else {
        return {
          success: false,
          error: data.error || 'Error en el registro'
        };
      }
    } catch (error) {
      console.error('Error in register:', error);
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Error de conexión'
      };
    }
  }

  async logout(): Promise<{ success: boolean; error?: string }> {
    try {
      await this.makeSecureRequest('/auth/logout/', {
        method: 'POST'
      });

      console.log('Logout exitoso');
    } catch (error) {
      console.warn('Error en logout del servidor:', error);
    } finally {
      this.clearTokens();
      window.dispatchEvent(new CustomEvent('auth:logout'));
    }

    return { success: true };
  }

  // ===========================================
  // VALIDACIONES DE ENTRADA
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

    if (credentials.email.length > 254) {
      return { valid: false, error: 'Email demasiado largo' };
    }

    if (credentials.password.length > 128) {
      return { valid: false, error: 'Contraseña demasiado larga' };
    }

    return { valid: true };
  }

  private validateRegistrationData(userData: RegisterData): { valid: boolean; error?: string } {
    if (!userData.firstName?.trim() || !userData.lastName?.trim()) {
      return { valid: false, error: 'Nombre y apellido son requeridos' };
    }

    if (userData.firstName.trim().length < 2 || userData.lastName.trim().length < 2) {
      return { valid: false, error: 'Nombre y apellido deben tener al menos 2 caracteres' };
    }

    if (userData.firstName.length > 30 || userData.lastName.length > 30) {
      return { valid: false, error: 'Nombre y apellido no pueden exceder 30 caracteres' };
    }

    const nameRegex = /^[a-zA-ZÀ-ÿ\s]+$/;
    if (!nameRegex.test(userData.firstName.trim()) || !nameRegex.test(userData.lastName.trim())) {
      return { valid: false, error: 'Nombre y apellido solo pueden contener letras' };
    }

    if (!userData.email?.trim()) {
      return { valid: false, error: 'El email es requerido' };
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(userData.email.trim())) {
      return { valid: false, error: 'Formato de email inválido' };
    }

    if (userData.email.length > 254) {
      return { valid: false, error: 'Email demasiado largo' };
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

    if (password.length > 128) {
      return { valid: false, error: 'Contraseña demasiado larga' };
    }

    const hasUpper = /[A-Z]/.test(password);
    const hasLower = /[a-z]/.test(password);
    const hasDigit = /\d/.test(password);
    const hasSymbol = /[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]/.test(password);

    if (!hasUpper || !hasLower || !hasDigit || !hasSymbol) {
      return { 
        valid: false, 
        error: 'La contraseña debe contener mayúsculas, minúsculas, números y símbolos' 
      };
    }

    const commonPatterns = ['123456', 'password', 'qwerty', 'admin', 'user'];
    const passwordLower = password.toLowerCase();
    
    for (const pattern of commonPatterns) {
      if (passwordLower.includes(pattern)) {
        return { valid: false, error: 'La contraseña contiene patrones muy comunes' };
      }
    }

    return { valid: true };
  }

  // ===========================================
  // MÉTODOS UTILITARIOS
  // ===========================================

  isAuthenticated(): boolean {
    return this.accessToken !== null && !this.isTokenExpired();
  }

  private isTokenExpired(): boolean {
    if (!this.tokenExpiryTime) return true;
    return Date.now() >= this.tokenExpiryTime - (60 * 1000);
  }

  getCurrentUser(): AuthUser | null {
    try {
      const userData = sessionStorage.getItem('user_data');
      return userData ? JSON.parse(userData) : null;
    } catch (error) {
      console.error('Error getting current user:', error);
      return null;
    }
  }

  getAccessToken(): string | null {
    return this.isTokenExpired() ? null : this.accessToken;
  }

  async authenticatedRequest<T>(
    endpoint: string, 
    options: RequestInit = {}
  ): Promise<T> {
    return this.makeSecureRequest<T>(endpoint, options);
  }

  async healthCheck(): Promise<boolean> {
    try {
      const response = await fetch(`${this.baseURL}/health/`, {
        method: 'GET',
        timeout: 5000
      } as any);
      return response.ok;
    } catch (error) {
      return false;
    }
  }

  // ===========================================
  // MÉTODOS DE VALIDACIÓN Y DIAGNÓSTICO
  // ===========================================

  private validateTokenIntegrity(): boolean {
    if (!this.accessToken) return false;

    try {
      const parts = this.accessToken.split('.');
      if (parts.length !== 3) return false;

      const payload = JSON.parse(atob(parts[1]));

      if (!payload.user_id || !payload.exp || !payload.email) {
        console.warn('Token JWT malformado - claims faltantes');
        return false;
      }

      if (payload.exp * 1000 < Date.now()) {
        console.warn('Token JWT expirado');
        return false;
      }

      return true;
    } catch (error) {
      console.error('Error validando integridad del token:', error);
      return false;
    }
  }

  getTokenInfo(): { userId?: number; email?: string; expiresAt?: number } | null {
    if (!this.accessToken || !this.validateTokenIntegrity()) {
      return null;
    }

    try {
      const payload = JSON.parse(atob(this.accessToken.split('.')[1]));
      return {
        userId: payload.user_id,
        email: payload.email,
        expiresAt: payload.exp * 1000
      };
    } catch (error) {
      console.error('Error extrayendo información del token:', error);
      return null;
    }
  }

  getServiceStatus(): {
    isAuthenticated: boolean;
    hasValidToken: boolean;
    tokenTimeRemaining: number;
    hasRefreshToken: boolean;
  } {
    const timeRemaining = this.tokenExpiryTime ? Math.max(0, this.tokenExpiryTime - Date.now()) : 0;
    
    return {
      isAuthenticated: this.isAuthenticated(),
      hasValidToken: this.validateTokenIntegrity(),
      tokenTimeRemaining: timeRemaining,
      hasRefreshToken: !!this.refreshToken,
    };
  }

  destroy(): void {
    if (this.refreshTimer) {
      clearTimeout(this.refreshTimer);
    }
    this.clearTokens();
  }
}

// ===========================================
// INSTANCIA SINGLETON Y EXPORTS
// ===========================================

export const authService = new SecureAuthService();

export const loginUser = (credentials: LoginCredentials) => authService.login(credentials);
export const registerUser = (userData: RegisterData) => authService.register(userData);
export const logoutUser = () => authService.logout();
export const isUserAuthenticated = () => authService.isAuthenticated();
export const getCurrentUser = () => authService.getCurrentUser();
export const checkAuthStatus = () => authService.checkAuthStatus();
export const getTokenInfo = () => authService.getTokenInfo();
export const getServiceStatus = () => authService.getServiceStatus();

// Event Listeners
window.addEventListener('beforeunload', () => {
  authService.destroy();
});

document.addEventListener('visibilitychange', () => {
  if (document.visibilityState === 'visible' && authService.isAuthenticated()) {
    authService.checkAuthStatus().then(result => {
      if (!result.success) {
        console.warn('Sesión inválida detectada al volver a la página');
        authService.logout();
      }
    });
  }
});

window.addEventListener('focus', async () => {
  if (authService.isAuthenticated()) {
    const status = authService.getServiceStatus();
    
    if (!status.hasValidToken) {
      console.warn('Estado inconsistente detectado al obtener foco');
      await authService.logout();
      window.location.href = '/login?expired=true';
    }
  }
});

// Monitoreo periódico cada 5 minutos
setInterval(() => {
  if (authService.isAuthenticated()) {
    const status = authService.getServiceStatus();
    
    if (!status.hasValidToken) {
      console.warn('Problemas detectados en el servicio de autenticación');
    }
  }
}, 5 * 60 * 1000);

export default authService;