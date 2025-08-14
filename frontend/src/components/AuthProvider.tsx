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

  // Verificar estado de autenticaciÃ³n al cargar
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
      console.error('Error verificando autenticaciÃ³n:', error);
      setUser(null);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    checkAuth();
  }, []);

  const login = async (credentials: { email: string; password: string }) => {
    setLoading(true);
    try {
      const response = await authService.login(credentials);
      if (response.success && response.user) {
        setUser(response.user);
        return { success: true };
      } else {
        return { success: false, error: response.error };
      }
    } catch (error) {
      return { success: false, error: 'Error de conexiÃ³n' };
    } finally {
      setLoading(false);
    }
  };

  const register = async (userData: { firstName: string; lastName: string; email: string; password: string }) => {
    setLoading(true);
    try {
      const response = await authService.register(userData);
      if (response.success && response.user) {
        setUser(response.user);
        return { success: true };
      } else {
        return { success: false, error: response.error };
      }
    } catch (error) {
      return { success: false, error: 'Error de conexiÃ³n' };
    } finally {
      setLoading(false);
    }
  };

  const logout = async () => {
    setLoading(true);
    try {
      await authService.logout();
      setUser(null);
    } catch (error) {
      console.error('Error al cerrar sesiÃ³n:', error);
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