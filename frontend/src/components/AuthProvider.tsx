import React, { createContext, useContext, useState, useEffect, useCallback, useRef } from 'react';
import type { ReactNode } from 'react';
import { authService, type AuthUser } from '../services/authService';
import { masterKeyService} from '../services/masterKeyService';

interface AuthContextType {
  user: AuthUser | null;
  isAuthenticated: boolean;
  hasMasterKey: boolean;
  showMasterKeyModal: boolean;
  loading: boolean;
  sessionExpired: boolean;
  connectionError: boolean;
  
  // Métodos de autenticación
  login: (credentials: { email: string; password: string }) => Promise<{ success: boolean; error?: string }>;
  register: (userData: { firstName: string; lastName: string; email: string; password: string }) => Promise<{ success: boolean; error?: string }>;
  logout: () => Promise<void>;
  
  // Gestión de Master Key
  setupMasterKey: (masterKey: string) => Promise<{ success: boolean; error?: string }>;
  closeMasterKeyModal: () => void;
  checkMasterKeyStatus: () => Promise<void>;
  
  // Métodos de control
  checkAuth: () => Promise<void>;
  refreshSession: () => Promise<void>;
  clearSessionExpiredState: () => void;
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
  // Estados principales
  const [user, setUser] = useState<AuthUser | null>(null);
  const [loading, setLoading] = useState(true);
  const [hasMasterKey, setHasMasterKey] = useState(false);
  const [showMasterKeyModal, setShowMasterKeyModal] = useState(false);
  
  // Estados de control de errores
  const [sessionExpired, setSessionExpired] = useState(false);
  const [connectionError, setConnectionError] = useState(false);
  
  // Refs para evitar múltiples ejecuciones
  const isCheckingMasterKey = useRef(false);
  const isCheckingAuth = useRef(false);
  const masterKeyChecked = useRef(false);

  // ===========================================
  // VERIFICACIÓN DE CLAVE MAESTRA - OPTIMIZADA
  // ===========================================

  const checkMasterKeyStatus = useCallback(async () => {
    if (!user || isCheckingMasterKey.current || masterKeyChecked.current) {
      return;
    }
    
    isCheckingMasterKey.current = true;
    
    try {
      console.log('🔑 Verificando estado de clave maestra...');
      const masterKeyResponse = await masterKeyService.hasMasterKey();
      
      if (masterKeyResponse.success) {
        setHasMasterKey(masterKeyResponse.hasMasterKey);
        
        // Mostrar modal solo si NO tiene clave maestra
        if (!masterKeyResponse.hasMasterKey) {
          console.log('🔑 Usuario sin clave maestra - mostrando modal');
          setShowMasterKeyModal(true);
        } else {
          console.log('🔑 Usuario ya tiene clave maestra');
          setShowMasterKeyModal(false);
        }
        
        // Marcar como verificado
        masterKeyChecked.current = true;
      } else {
        console.warn('🔑 Error verificando clave maestra:', masterKeyResponse.error);
        setHasMasterKey(false);
        setShowMasterKeyModal(true);
      }
    } catch (error) {
      console.error('🔑 Error en checkMasterKeyStatus:', error);
      setHasMasterKey(false);
      setShowMasterKeyModal(true);
    } finally {
      isCheckingMasterKey.current = false;
    }
  }, []); // ✅ Sin dependencias para evitar bucles

  // ===========================================
  // VERIFICACIÓN DE AUTENTICACIÓN - OPTIMIZADA
  // ===========================================

  const handleUnauthenticated = useCallback(() => {
    const hadUser = !!user;
    
    setUser(null);
    setHasMasterKey(false);
    setShowMasterKeyModal(false);
    masterKeyChecked.current = false;
    
    // Si había un usuario antes, significa que la sesión expiró
    if (hadUser) {
      setSessionExpired(true);
    }
  }, [user]);

  const checkAuth = useCallback(async () => {
  if (isCheckingAuth.current) {
    return;
  }

  console.log('🔍 Iniciando verificación de autenticación...');
  setLoading(true);
  setConnectionError(false);
  isCheckingAuth.current = true;
  
  try {
    const isHealthy = await authService.healthCheck();
    if (!isHealthy) {
      console.warn('⚠️ Servidor no disponible');
      setConnectionError(true);
      return;
    }

    const response = await authService.checkAuthStatus();
    console.log('🔍 Respuesta auth:', response);
    
    if (response.success && response.user) {
      console.log('✅ Usuario autenticado:', response.user);
      setUser(response.user);
      setSessionExpired(false);
      
      // ✅ CAMBIO PRINCIPAL: Usar el hasMasterKey que viene del servidor
      const serverHasMasterKey = response.user.hasMasterKey || false;
      setHasMasterKey(serverHasMasterKey);
      
      // Mostrar modal solo si NO tiene master key
      if (!serverHasMasterKey) {
        console.log('🔑 Usuario sin clave maestra detectado - mostrando modal');
        setShowMasterKeyModal(true);
        masterKeyChecked.current = true;
      } else {
        console.log('🔑 Usuario con clave maestra confirmada');
        setShowMasterKeyModal(false);
        masterKeyChecked.current = true;
      }
      
    } else {
      console.log('❌ Usuario no autenticado');
      handleUnauthenticated();
    }
  } catch (error) {
    console.error('❌ Error verificando autenticación:', error);
    
    if (error instanceof Error && error.message.includes('conexión')) {
      setConnectionError(true);
    } else {
      handleUnauthenticated();
    }
  } finally {
    setLoading(false);
    isCheckingAuth.current = false;
  }
}, [handleUnauthenticated]);

  // ===========================================
  // EFECTOS DE INICIALIZACIÓN - OPTIMIZADOS
  // ===========================================

  // Solo ejecutar checkAuth una vez al montar el componente
  useEffect(() => {
    checkAuth();
  }, []); // ✅ Array vacío para ejecutar solo una vez

  // Listener para eventos de autenticación
  useEffect(() => {
    const handleSessionExpired = () => {
      console.log('⚠️ Sesión expirada detectada');
      setSessionExpired(true);
      handleUnauthenticated();
    };

    const handleLogout = () => {
      console.log('👋 Logout detectado');
      handleUnauthenticated();
    };

    // Escuchar eventos globales de autenticación
    window.addEventListener('auth:sessionExpired', handleSessionExpired);
    window.addEventListener('auth:logout', handleLogout);

    return () => {
      window.removeEventListener('auth:sessionExpired', handleSessionExpired);
      window.removeEventListener('auth:logout', handleLogout);
    };
  }, [handleUnauthenticated]);

  // ===========================================
  // MÉTODOS DE AUTENTICACIÓN - OPTIMIZADOS
  // ===========================================

  const login = async (credentials: { email: string; password: string }) => {
    try {
      setLoading(true);
      setConnectionError(false);
      setSessionExpired(false);
      masterKeyChecked.current = false;

      const response = await authService.login(credentials);
      
      if (response.success && response.user) {
        console.log('Login exitoso:', response.user);
        setUser(response.user);
        
        // USAR directamente el hasMasterKey que viene del servidor
        const serverHasMasterKey = response.user.hasMasterKey || false;
        setHasMasterKey(serverHasMasterKey);
        
        // Mostrar modal si no tiene master key
        if (!serverHasMasterKey) {
          console.log('Usuario sin clave maestra - mostrando modal');
          setShowMasterKeyModal(true);
        } else {
          console.log('Usuario con clave maestra');
          setShowMasterKeyModal(false);
        }
        
        masterKeyChecked.current = true;
        
        return { success: true };
      } else {
        return { 
          success: false, 
          error: response.error || 'Error en el inicio de sesión' 
        };
      }
    } catch (error) {
      console.error('Error en login del provider:', error);
      
      if (error instanceof Error && error.message.includes('conexión')) {
        setConnectionError(true);
        return { success: false, error: 'Error de conexión. Verifica tu internet.' };
      }
      
      return { success: false, error: 'Error de conexión' };
    } finally {
      setLoading(false);
    }
  };

  const register = async (userData: { 
    firstName: string; 
    lastName: string; 
    email: string; 
    password: string; 
  }) => {
    try {
      setLoading(true);
      setConnectionError(false);
      masterKeyChecked.current = false;

      const response = await authService.register(userData);
      
      if (response.success && response.user) {
        console.log('Registro exitoso:', response.user);
        setUser(response.user);
        
        // Los nuevos usuarios SIEMPRE necesitan configurar clave maestra
        // Pero verificar el valor del servidor por si acaso
        const serverHasMasterKey = response.user.hasMasterKey || false;
        setHasMasterKey(serverHasMasterKey);
        
        // Para nuevos registros, SIEMPRE mostrar modal
        setShowMasterKeyModal(true);
        masterKeyChecked.current = true;
        
        return { success: true };
      } else {
        return { 
          success: false, 
          error: response.error || 'Error en el registro' 
        };
      }
    } catch (error) {
      console.error('Error en register del provider:', error);
      
      if (error instanceof Error && error.message.includes('conexión')) {
        setConnectionError(true);
        return { success: false, error: 'Error de conexión. Verifica tu internet.' };
      }
      
      return { success: false, error: 'Error de conexión' };
    } finally {
      setLoading(false);
    }
  };

  const logout = async () => {
    console.log('🚪 Cerrando sesión...');
    setLoading(true);
    
    try {
      await authService.logout();
      console.log('✅ Sesión cerrada exitosamente');
    } catch (error) {
      console.error('❌ Error al cerrar sesión:', error);
    } finally {
      // Limpiar estado local siempre
      setUser(null);
      setHasMasterKey(false);
      setShowMasterKeyModal(false);
      setSessionExpired(false);
      setConnectionError(false);
      setLoading(false);
      masterKeyChecked.current = false;
      isCheckingMasterKey.current = false;
      isCheckingAuth.current = false;
    }
  };

  // ===========================================
  // GESTIÓN DE MASTER KEY - OPTIMIZADA
  // ===========================================

  const setupMasterKey = async (masterKey: string): Promise<{ success: boolean; error?: string }> => {
    try {
      console.log('🔑 Configurando clave maestra...');
      const response = await masterKeyService.setMasterKey(masterKey);
      
      if (response.success) {
        console.log('✅ Clave maestra configurada exitosamente');
        setHasMasterKey(true);
        setShowMasterKeyModal(false);
        masterKeyChecked.current = true;
        return { success: true };
      } else {
        console.error('❌ Error configurando clave maestra:', response.error);
        return { 
          success: false, 
          error: response.error || 'Error al configurar la clave maestra' 
        };
      }
    } catch (error) {
      console.error('❌ Error configurando clave maestra:', error);
      
      if (error instanceof Error && error.message.includes('conexión')) {
        return { success: false, error: 'Error de conexión. Intenta nuevamente.' };
      }
      
      return { success: false, error: 'Error de conexión' };
    }
  };

  const closeMasterKeyModal = () => {
    // Solo permitir cerrar si ya tiene clave maestra configurada
    if (hasMasterKey) {
      console.log('🔑 Cerrando modal - usuario ya tiene clave maestra');
      setShowMasterKeyModal(false);
    } else {
      console.log('🔑 No se puede cerrar modal - clave maestra es obligatoria');
    }
  };

  // ===========================================
  // MÉTODOS UTILITARIOS
  // ===========================================

  const refreshSession = async () => {
    console.log('🔄 Refrescando sesión...');
    masterKeyChecked.current = false;
    await checkAuth();
  };

  const clearSessionExpiredState = () => {
    setSessionExpired(false);
  };

  // ===========================================
  // VALOR DEL CONTEXTO
  // ===========================================

  const value: AuthContextType = {
    // Estado
    user,
    isAuthenticated: !!user && authService.isAuthenticated(),
    hasMasterKey,
    showMasterKeyModal,
    loading,
    sessionExpired,
    connectionError,
    
    // Métodos de autenticación
    login,
    register,
    logout,
    
    // Gestión de Master Key
    setupMasterKey,
    closeMasterKeyModal,
    checkMasterKeyStatus,
    
    // Métodos de control
    checkAuth,
    refreshSession,
    clearSessionExpiredState,
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
};

// Hook personalizado para verificar autenticación con reintento
export const useAuthWithRetry = () => {
  const auth = useAuth();
  const [retryCount, setRetryCount] = useState(0);

  const retryAuth = useCallback(async () => {
    if (retryCount < 3) {
      console.log(`🔄 Reintentando autenticación (${retryCount + 1}/3)...`);
      setRetryCount(prev => prev + 1);
      await auth.checkAuth();
      
      // Reset counter si es exitoso
      if (auth.isAuthenticated) {
        setRetryCount(0);
      }
    }
  }, [auth, retryCount]);

  return { ...auth, retryAuth, canRetry: retryCount < 3 };
};

export default AuthProvider;