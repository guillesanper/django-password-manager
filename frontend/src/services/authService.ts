// services/authService.ts - URLs corregidas para coincidir con Django
export interface AuthUser {
  id: number;
  username: string;
  email: string;
  firstName: string;
  lastName: string;
  isAuthenticated: boolean;
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

class AuthService {
  private baseURL = 'http://localhost:8000';

  // Obtener el token CSRF de Django (mejorado)
  private getCSRFToken(): string | null {
    // Intentar obtener de cookies
    const cookies = document.cookie.split(';');
    for (let cookie of cookies) {
      const [name, value] = cookie.trim().split('=');
      if (name === 'csrftoken') {
        return value;
      }
    }
    
    // Intentar obtener del meta tag (alternativa)
    const csrfMeta = document.querySelector('meta[name="csrf-token"]');
    if (csrfMeta) {
      return csrfMeta.getAttribute('content');
    }
    
    return null;
  }

  // Obtener token CSRF del servidor si no existe
  private async ensureCSRFToken(): Promise<string | null> {
    let token = this.getCSRFToken();
    
    if (!token) {
      try {
        const response = await fetch(this.baseURL + '/admin/', {
          method: 'GET',
          credentials: 'include',
        });
        token = this.getCSRFToken();
      } catch (error) {
        console.warn('No se pudo obtener el token CSRF:', error);
      }
    }
    
    return token;
  }

  // Headers comunes para las peticiones (mejorado)
  private async getHeaders(): Promise<Record<string, string>> {
    const csrfToken = await this.ensureCSRFToken();
    return {
      'Content-Type': 'application/json',
      'X-CSRFToken': csrfToken || '',
    };
  }

  // Verificar estado de autenticación
  async checkAuthStatus(): Promise<AuthResponse> {
    try {
      const response = await fetch(this.baseURL + '/auth/check/', {
        method: 'GET',
        credentials: 'include',
      });

      const data = await response.json();
      
      if (response.ok) {
        return {
          success: data.isAuthenticated,
          user: data.isAuthenticated ? data.user : null
        };
      } else {
        return {
          success: false,
          error: 'Error al verificar autenticación'
        };
      }
    } catch (error) {
      console.error('Error checking auth status:', error);
      return {
        success: false,
        error: 'Error de conexión'
      };
    }
  }

  // Iniciar sesión (actualizado)
  async login(credentials: LoginCredentials): Promise<AuthResponse> {
    try {
      const headers = await this.getHeaders();
      
      const response = await fetch(this.baseURL + '/auth/login/', {
        method: 'POST',
        headers,
        credentials: 'include',
        body: JSON.stringify(credentials)
      });

      const data = await response.json();

      if (response.ok && data.success) {
        // Actualizar datos globales de Django si existen
        if (window.DjangoData) {
          window.DjangoData.user = {
            ...data.user,
            isAuthenticated: true
          };
        }
        
        return {
          success: true,
          user: data.user
        };
      } else {
        return {
          success: false,
          error: data.error || 'Error en el inicio de sesión'
        };
      }
    } catch (error) {
      console.error('Error in login:', error);
      return {
        success: false,
        error: 'Error de conexión. Verifica tu conexión a internet.'
      };
    }
  }

  // Registrar usuario (actualizado)
  async register(userData: RegisterData): Promise<AuthResponse> {
    try {
      const headers = await this.getHeaders();
      
      const response = await fetch(this.baseURL + '/auth/register/', {
        method: 'POST',
        headers,
        credentials: 'include',
        body: JSON.stringify({
          first_name: userData.firstName,
          last_name: userData.lastName,
          email: userData.email,
          password: userData.password
        })
      });

      const data = await response.json();

      if (response.ok && data.success) {
        // Actualizar datos globales de Django si existen
        if (window.DjangoData) {
          window.DjangoData.user = {
            ...data.user,
            isAuthenticated: true
          };
        }
        
        return {
          success: true,
          user: data.user
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
        error: 'Error de conexión. Verifica tu conexión a internet.'
      };
    }
  }

  // Cerrar sesión (actualizado)
  async logout(): Promise<{ success: boolean; error?: string }> {
    try {
      const csrfToken = await this.ensureCSRFToken();
      
      const response = await fetch('/auth/logout/', {
        method: 'POST',
        headers: {
          'X-CSRFToken': csrfToken || '',
        },
        credentials: 'include'
      });

      if (response.ok) {
        // Actualizar datos globales de Django
        if (window.DjangoData) {
          window.DjangoData.user = {
            id: 0,
            username: '',
            email: '',
            firstName: '',
            lastName: '',
            isAuthenticated: false
          };
        }
        
        return { success: true };
      } else {
        const data = await response.json();
        return {
          success: false,
          error: data.error || 'Error al cerrar sesión'
        };
      }
    } catch (error) {
      console.error('Error in logout:', error);
      return {
        success: false,
        error: 'Error de conexión'
      };
    }
  }

  // Verificar si el usuario está autenticado (usando datos locales)
  isAuthenticated(): boolean {
    return window.DjangoData?.user?.isAuthenticated || false;
  }

  // Obtener usuario actual
  getCurrentUser(): AuthUser | null {
    if (window.DjangoData?.user?.isAuthenticated) {
      return window.DjangoData.user;
    }
    return null;
  }
}

// Crear una instancia del servicio para exportar
export const authService = new AuthService();

// También exportar las funciones individuales para compatibilidad
export const loginUser = (credentials: LoginCredentials) => authService.login(credentials);
export const registerUser = (userData: RegisterData) => authService.register(userData);
export const logoutUser = () => authService.logout();
export const isUserAuthenticated = () => authService.isAuthenticated();
export const getCurrentUser = () => authService.getCurrentUser();
export const checkAuthStatus = () => authService.checkAuthStatus();