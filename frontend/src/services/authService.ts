// services/authService.ts - Versión corregida con persistencia mejorada

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
  private isRefreshing = false;
  private refreshPromise: Promise<void> | null = null;
  private storageKey = 'secure_auth_data';
  
  constructor() {
    this.loadTokensFromStorage();
    this.setupAutomaticTokenRefresh();
    this.setupVisibilityChangeHandler();
    this.setupStorageListener();
  }

  // ===========================================
  // GESTIÓN MEJORADA DE ALMACENAMIENTO
  // ===========================================

  private saveTokensToStorage(tokens: JWTTokens): void {
    try {
      const tokenData = {
        access: tokens.access,
        refresh: tokens.refresh,
        expiresAt: tokens.expiresAt || this.calculateTokenExpiry(tokens.access),
        timestamp: Date.now(),
        version: '1.0' // Para futuras migraciones
      };

      // CAMBIO PRINCIPAL: Usar localStorage para persistir tras recargas
      localStorage.setItem(this.storageKey, JSON.stringify(tokenData));
      
      // También mantener en sessionStorage como respaldo
      sessionStorage.setItem(this.storageKey, JSON.stringify(tokenData));
      
      this.accessToken = tokens.access;
      this.refreshToken = tokens.refresh;
      this.tokenExpiryTime = tokenData.expiresAt;
      
      console.log('Tokens guardados correctamente');
    } catch (error) {
      console.error('Error saving tokens:', error);
    }
  }

  private loadTokensFromStorage(): void {
    try {
      // Intentar cargar desde localStorage primero (persiste tras recargas)
      let stored = localStorage.getItem(this.storageKey);
      
      // Si no está en localStorage, intentar sessionStorage
      if (!stored) {
        stored = sessionStorage.getItem(this.storageKey);
      }

      if (stored) {
        const tokenData = JSON.parse(stored);
        const now = Date.now();
        
        // Verificar que no esté expirado
        if (tokenData.expiresAt && now < tokenData.expiresAt) {
          this.accessToken = tokenData.access;
          this.refreshToken = tokenData.refresh;
          this.tokenExpiryTime = tokenData.expiresAt;
          
          // Sincronizar ambos almacenamientos
          localStorage.setItem(this.storageKey, stored);
          sessionStorage.setItem(this.storageKey, stored);
          
          console.log('Tokens cargados desde almacenamiento');
        } else {
          console.log('Tokens expirados en almacenamiento');
          this.clearTokens();
        }
      } else {
        console.log('No se encontraron tokens en almacenamiento');
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
      localStorage.removeItem(this.storageKey);
      sessionStorage.removeItem(this.storageKey);
      localStorage.removeItem('user_data');
      sessionStorage.removeItem('user_data');
    } catch (error) {
      console.error('Error clearing tokens:', error);
    }

    if (this.refreshTimer) {
      clearTimeout(this.refreshTimer);
      this.refreshTimer = null;
    }
  }

  // Listener para cambios en localStorage (pestañas múltiples)
  private setupStorageListener(): void {
    window.addEventListener('storage', (e) => {
      if (e.key === this.storageKey) {
        if (e.newValue === null) {
          // Tokens eliminados en otra pestaña
          console.log('Logout detectado en otra pestaña');
          this.handleAuthError();
        } else if (e.newValue !== e.oldValue) {
          // Tokens actualizados en otra pestaña
          console.log('Tokens actualizados en otra pestaña');
          this.loadTokensFromStorage();
        }
      }
    });
  }

  private calculateTokenExpiry(accessToken: string): number {
    try {
      const payload = JSON.parse(atob(accessToken.split('.')[1]));
      return payload.exp * 1000;
    } catch (error) {
      // Fallback: 15 minutos desde ahora
      return Date.now() + (15 * 60 * 1000);
    }
  }

  // ===========================================
  // GESTIÓN DE CSRF MEJORADA
  // ===========================================

  private async getCSRFToken(): Promise<string> {
    // Primero intentar obtener desde las cookies
    const cookies = document.cookie.split(';');
    for (let cookie of cookies) {
      const [name, value] = cookie.trim().split('=');
      if (name === 'csrftoken') {
        return value;
      }
    }

    // Si no está en cookies, hacer request al endpoint de CSRF
    try {
      const response = await fetch(`${this.baseURL}/auth/csrf/`, {
        method: 'GET',
        credentials: 'include',
      });
      
      if (response.ok) {
        const data = await response.json();
        if (data.csrfToken) {
          return data.csrfToken;
        }
      }
      
      // Verificar si ahora está en las cookies
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

    // Agregar CSRF token
    try {
      const csrfToken = await this.getCSRFToken();
      headers['X-CSRFToken'] = csrfToken;
    } catch (error) {
      console.warn('CSRF token no disponible:', error);
    }

    // Agregar JWT token si está disponible
    if (this.accessToken && !this.isTokenExpired()) {
      headers['Authorization'] = `Bearer ${this.accessToken}`;
    }

    return headers;
  }

  // ===========================================
  // CONFIGURACIÓN DE RENOVACIÓN AUTOMÁTICA
  // ===========================================

  private setupAutomaticTokenRefresh(): void {
    const scheduleNextRefresh = () => {
      if (this.refreshTimer) {
        clearTimeout(this.refreshTimer);
      }

      if (!this.tokenExpiryTime || !this.refreshToken) {
        return;
      }

      const now = Date.now();
      const timeUntilExpiry = this.tokenExpiryTime - now;
      
      // Renovar cuando queden 5 minutos
      const refreshBuffer = 5 * 60 * 1000;
      const timeUntilRefresh = Math.max(1000, timeUntilExpiry - refreshBuffer);

      console.log(`Programando renovación en ${Math.round(timeUntilRefresh / 1000 / 60)} minutos`);

      this.refreshTimer = setTimeout(async () => {
        try {
          console.log('Iniciando renovación automática...');
          await this.refreshAccessToken();
          console.log('Token renovado automáticamente');
          scheduleNextRefresh();
        } catch (error) {
          console.error('Error en renovación automática:', error);
          this.handleAuthError();
        }
      }, timeUntilRefresh);
    };

    scheduleNextRefresh();
  }

  private setupVisibilityChangeHandler(): void {
    document.addEventListener('visibilitychange', async () => {
      if (document.visibilityState === 'visible' && this.accessToken) {
        console.log('Página visible - verificando estado del token');
        
        if (this.isTokenExpired()) {
          console.log('Token expirado detectado');
          try {
            await this.refreshAccessToken();
            console.log('Token renovado tras volver a la página');
          } catch (error) {
            console.error('Error renovando token:', error);
            this.handleAuthError();
          }
        }
      }
    });
  }

  // ===========================================
  // GESTIÓN DE TOKENS JWT
  // ===========================================

  private async refreshAccessToken(): Promise<void> {
    if (!this.refreshToken) {
      throw new Error('No refresh token available');
    }

    if (this.isRefreshing) {
      if (this.refreshPromise) {
        return this.refreshPromise;
      }
      throw new Error('Token refresh already in progress');
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
    try {
      console.log('Renovando token...');
      
      const headers: Record<string, string> = {
        'Content-Type': 'application/json',
      };

      // Agregar CSRF si es posible
      try {
        const csrfToken = await this.getCSRFToken();
        headers['X-CSRFToken'] = csrfToken;
      } catch (error) {
        console.warn('No se pudo obtener CSRF para refresh');
      }
      
      const response = await fetch(`${this.baseURL}/api/token/refresh/`, {
        method: 'POST',
        headers,
        credentials: 'include',
        body: JSON.stringify({
          refresh: this.refreshToken
        })
      });

      if (!response.ok) {
        throw new Error(`Token refresh failed: ${response.status}`);
      }

      const data = await response.json();
      
      if (data.access) {
        const newTokens: JWTTokens = {
          access: data.access,
          refresh: data.refresh || this.refreshToken,
        };

        this.saveTokensToStorage(newTokens);
        this.setupAutomaticTokenRefresh();
        console.log('Token renovado exitosamente');
      } else {
        throw new Error('Invalid refresh response');
      }
    } catch (error) {
      console.error('Error renovando token:', error);
      throw error;
    }
  }

  // ===========================================
  // MANEJO DE RESPUESTAS
  // ===========================================

  private async handleResponse<T>(response: Response): Promise<T> {
    let data;
    
    try {
      data = await response.json();
    } catch (error) {
      throw new Error('Respuesta del servidor inválida');
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

      if (data && typeof data === 'object' && 'success' in data) {
        return data as T;
      }

      const errorMessages: Record<number, string> = {
        400: 'Datos inválidos',
        401: 'No autorizado',
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
    if (this.accessToken && this.isTokenExpired()) {
      try {
        await this.refreshAccessToken();
      } catch (error) {
        console.error('Error renovando token antes de request:', error);
        this.handleAuthError();
        throw error;
      }
    }

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

  private handleAuthError(): void {
    console.log('Manejando error de autenticación');
    this.clearTokens();
    window.dispatchEvent(new CustomEvent('auth:sessionExpired'));
    
    if (window.location.pathname !== '/login') {
      window.location.href = '/login?expired=true';
    }
  }

  // ===========================================
  // MÉTODOS PÚBLICOS
  // ===========================================

  async checkAuthStatus(): Promise<AuthResponse> {
    try {
      if (!this.accessToken) {
        console.log('No hay token de acceso');
        return { success: false };
      }

      if (this.isTokenExpired()) {
        console.log('Token expirado, intentando renovar...');
        try {
          await this.refreshAccessToken();
          console.log('Token renovado exitosamente');
        } catch (error) {
          console.log('No se pudo renovar el token');
          this.clearTokens();
          return { success: false };
        }
      }

      const data = await this.makeSecureRequest<any>('/auth/check/');

      if (data.success) {
        // Guardar datos del usuario
        try {
          localStorage.setItem('user_data', JSON.stringify(data.user));
          sessionStorage.setItem('user_data', JSON.stringify(data.user));
        } catch (error) {
          console.warn('Error guardando datos de usuario:', error);
        }
      }

      return {
        success: data.success,
        user: data.success ? data.user : null
      };
    } catch (error) {
      console.error('Error checking auth status:', error);
      
      if (error instanceof Error && error.message.includes('401')) {
        this.clearTokens();
      }
      
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
          password: credentials.password
        })
      });

      console.log('Respuesta login:', data);

      if (data.success && data.user && data.tokens) {
        this.saveTokensToStorage(data.tokens);
        
        // Guardar datos del usuario
        try {
          localStorage.setItem('user_data', JSON.stringify(data.user));
          sessionStorage.setItem('user_data', JSON.stringify(data.user));
        } catch (error) {
          console.warn('Error guardando datos de usuario:', error);
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
      console.error('Error en login:', error);
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
          localStorage.setItem('user_data', JSON.stringify(data.user));
          sessionStorage.setItem('user_data', JSON.stringify(data.user));
        } catch (error) {
          console.warn('Error guardando datos de usuario:', error);
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
      console.error('Error en register:', error);
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
      console.log('Logout del servidor exitoso');
    } catch (error) {
      console.warn('Error en logout del servidor:', error);
    } finally {
      this.clearTokens();
      window.dispatchEvent(new CustomEvent('auth:logout'));
    }

    return { success: true };
  }

  // ===========================================
  // MÉTODOS UTILITARIOS
  // ===========================================

  isAuthenticated(): boolean {
    const hasValidToken = this.accessToken !== null && !this.isTokenExpired();
    console.log(`isAuthenticated: ${hasValidToken}`);
    return hasValidToken;
  }

  private isTokenExpired(): boolean {
    if (!this.tokenExpiryTime) return true;
    
    const buffer = 60 * 1000; // 1 minuto
    const isExpired = Date.now() >= (this.tokenExpiryTime - buffer);
    
    if (isExpired) {
      console.log('Token expirado detectado');
    }
    
    return isExpired;
  }

  getCurrentUser(): AuthUser | null {
    try {
      // Intentar desde localStorage primero
      let userData = localStorage.getItem('user_data');
      if (!userData) {
        userData = sessionStorage.getItem('user_data');
      }
      return userData ? JSON.parse(userData) : null;
    } catch (error) {
      console.error('Error obteniendo usuario actual:', error);
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

  // Validaciones (mantener las existentes)
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

  getTokenInfo(): { userId?: number; email?: string; expiresAt?: number } | null {
    if (!this.accessToken) return null;

    try {
      const payload = JSON.parse(atob(this.accessToken.split('.')[1]));
      return {
        userId: payload.user_id,
        email: payload.email,
        expiresAt: payload.exp * 1000
      };
    } catch (error) {
      return null;
    }
  }

  destroy(): void {
    if (this.refreshTimer) {
      clearTimeout(this.refreshTimer);
    }
    this.clearTokens();
  }
}

export const authService = new SecureAuthService();
export default authService;