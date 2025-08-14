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

  // Procesar respuesta HTTP y manejar errores
  private async processResponse(response: Response): Promise<any> {
    let data;
    
    try {
      data = await response.json();
    } catch (error) {
      // Si no se puede parsear el JSON, es un error del servidor
      throw new Error('Error del servidor. Por favor, inténtalo más tarde.');
    }

    if (!response.ok) {
      // Si la respuesta tiene un error específico, usarlo
      if (data.error) {
        throw new Error(data.error);
      }
      
      // Si no, usar el código de estado
      switch (response.status) {
        case 400:
          throw new Error('Datos inválidos. Verifica la información ingresada.');
        case 401:
          throw new Error('Credenciales incorrectas.');
        case 403:
          throw new Error('No tienes permisos para realizar esta acción.');
        case 404:
          throw new Error('Recurso no encontrado.');
        case 429:
          throw new Error('Demasiados intentos. Espera un momento antes de intentar nuevamente.');
        case 500:
          throw new Error('Error interno del servidor. Inténtalo más tarde.');
        default:
          throw new Error('Ocurrió un error inesperado. Inténtalo nuevamente.');
      }
    }

    return data;
  }

  // Verificar estado de autenticación
  async checkAuthStatus(): Promise<AuthResponse> {
    try {
      const response = await fetch(this.baseURL + '/auth/check/', {
        method: 'GET',
        credentials: 'include',
        headers: {
          'Accept': 'application/json',
        },
      });

      const data = await this.processResponse(response);
      
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

  // Iniciar sesión (mejorado)
  async login(credentials: LoginCredentials): Promise<AuthResponse> {
    try {
      // Validaciones de entrada
      if (!credentials.email?.trim()) {
        return {
          success: false,
          error: 'El email es requerido'
        };
      }

      if (!credentials.password) {
        return {
          success: false,
          error: 'La contraseña es requerida'
        };
      }

      // Validar formato de email
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailRegex.test(credentials.email.trim())) {
        return {
          success: false,
          error: 'El formato del email no es válido'
        };
      }

      const headers = await this.getHeaders();
      
      const response = await fetch(this.baseURL + '/auth/login/', {
        method: 'POST',
        headers,
        credentials: 'include',
        body: JSON.stringify({
          email: credentials.email.trim(),
          password: credentials.password
        })
      });

      const data = await this.processResponse(response);

      if (data.success && data.user) {
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
          error: data.error || 'Email o contraseña incorrectos'
        };
      }
    } catch (error) {
      console.error('Error in login:', error);
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Error de conexión. Verifica tu conexión a internet.'
      };
    }
  }

  // Registrar usuario (mejorado)
  async register(userData: RegisterData): Promise<AuthResponse> {
    try {
      // Validaciones de entrada
      if (!userData.firstName?.trim()) {
        return {
          success: false,
          error: 'El nombre es requerido'
        };
      }

      if (!userData.lastName?.trim()) {
        return {
          success: false,
          error: 'El apellido es requerido'
        };
      }

      if (!userData.email?.trim()) {
        return {
          success: false,
          error: 'El email es requerido'
        };
      }

      if (!userData.password) {
        return {
          success: false,
          error: 'La contraseña es requerida'
        };
      }

      // Validar formato de email
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailRegex.test(userData.email.trim())) {
        return {
          success: false,
          error: 'El formato del email no es válido'
        };
      }

      // Validar longitud de contraseña
      if (userData.password.length < 8) {
        return {
          success: false,
          error: 'La contraseña debe tener al menos 8 caracteres'
        };
      }

      // Validar nombres (solo letras y espacios)
      const nameRegex = /^[a-zA-ZÀ-ÿ\s]+$/;
      if (!nameRegex.test(userData.firstName.trim())) {
        return {
          success: false,
          error: 'El nombre solo puede contener letras'
        };
      }

      if (!nameRegex.test(userData.lastName.trim())) {
        return {
          success: false,
          error: 'El apellido solo puede contener letras'
        };
      }

      const headers = await this.getHeaders();
      
      const response = await fetch(this.baseURL + '/auth/register/', {
        method: 'POST',
        headers,
        credentials: 'include',
        body: JSON.stringify({
          first_name: userData.firstName.trim(),
          last_name: userData.lastName.trim(),
          email: userData.email.trim(),
          password: userData.password
        })
      });

      const data = await this.processResponse(response);

      if (data.success && data.user) {
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
          error: data.error || 'Error al crear la cuenta'
        };
      }
    } catch (error) {
      console.error('Error in register:', error);
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Error de conexión. Verifica tu conexión a internet.'
      };
    }
  }

  // Cerrar sesión (mejorado)
  async logout(): Promise<{ success: boolean; error?: string }> {
    try {
      const csrfToken = await this.ensureCSRFToken();
      
      const response = await fetch(this.baseURL + '/auth/logout/', {
        method: 'POST',
        headers: {
          'X-CSRFToken': csrfToken || '',
          'Accept': 'application/json',
        },
        credentials: 'include'
      });

      const data = await this.processResponse(response);

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
    } catch (error) {
      console.error('Error in logout:', error);
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Error al cerrar sesión'
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