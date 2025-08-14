import React, { createContext, useContext, useState, useEffect } from 'react';
import type { ReactNode } from 'react';
import { authService, type AuthUser } from '../services/authService';

interface AuthContextType {
  user: AuthUser | null;
  isAuthenticated: boolean;
  login: (credentials: { email: string; password: string }) => Promise<{ success: boolean; error?: string }>;
  register: (userData: { firstName: string; lastName: string; email: string; password: string }) => Promise<{ success: boolean; error?: string }>;
  logout: () => Promise<void>;
  loading: boolean;
  checkAuth: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const useAuth = (): AuthContextType => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth debe ser usado dentro de un AuthProvider');
  }
  return context;
};

interface AuthProviderProps {
  children: ReactNode;
}

export const AuthProvider: React.FC<AuthProviderProps> = ({ children }) => {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [loading, setLoading] = useState(true);

  // Verificar estado de autenticación al cargar
  const checkAuth = async () => {
    setLoading(true);
    try {
      const response = await authService.checkAuthStatus();
      if (response.success && response.user) {
        setUser(response.user);
      } else {
        setUser(null);
      }
    } catch (error) {
      console.error('Error verificando autenticación:', error);
      setUser(null);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    checkAuth();
  }, []);

  const login = async (credentials: { email: string; password: string }) => {
    // NO cambiar el estado de loading aquí, dejarlo al componente
    // setLoading(true);
    try {
      const response = await authService.login(credentials);
      if (response.success && response.user) {
        setUser(response.user);
        return { success: true };
      } else {
        // NO cambiar user a null si hay error, mantener el estado
        return { success: false, error: response.error || 'Error en el inicio de sesión' };
      }
    } catch (error) {
      console.error('Error en login del provider:', error);
      return { success: false, error: 'Error de conexión' };
    }
    // NO cambiar loading aquí
    // finally {
    //   setLoading(false);
    // }
  };

  const register = async (userData: { firstName: string; lastName: string; email: string; password: string }) => {
    // NO cambiar el estado de loading aquí, dejarlo al componente
    // setLoading(true);
    try {
      const response = await authService.register(userData);
      if (response.success && response.user) {
        setUser(response.user);
        return { success: true };
      } else {
        // NO cambiar user a null si hay error, mantener el estado
        return { success: false, error: response.error || 'Error en el registro' };
      }
    } catch (error) {
      console.error('Error en register del provider:', error);
      return { success: false, error: 'Error de conexión' };
    }
    // NO cambiar loading aquí
    // finally {
    //   setLoading(false);
    // }
  };

  const logout = async () => {
    setLoading(true);
    try {
      await authService.logout();
      setUser(null);
    } catch (error) {
      console.error('Error al cerrar sesión:', error);
      // Incluso si hay error, limpiar el estado local
      setUser(null);
    } finally {
      setLoading(false);
    }
  };

  const value: AuthContextType = {
    user,
    isAuthenticated: !!user,
    login,
    register,
    logout,
    loading,
    checkAuth
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
};