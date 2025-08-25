import React, { createContext, useContext, useState, useEffect } from 'react';
import type { ReactNode } from 'react';
import { authService, type AuthUser } from '../services/authService';
import { masterKeyService, type MasterKeyResponse } from '../services/masterKeyService';

interface AuthContextType {
  user: AuthUser | null;
  isAuthenticated: boolean;
  hasMasterKey: boolean;
  showMasterKeyModal: boolean;
  login: (credentials: { email: string; password: string }) => Promise<{ success: boolean; error?: string }>;
  register: (userData: { firstName: string; lastName: string; email: string; password: string }) => Promise<{ success: boolean; error?: string }>;
  logout: () => Promise<void>;
  setupMasterKey: (masterKey: string) => Promise<{ success: boolean; error?: string }>;
  closeMasterKeyModal: () => void;
  loading: boolean;
  checkAuth: () => Promise<void>;
  checkMasterKeyStatus: () => Promise<void>;
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
  const [hasMasterKey, setHasMasterKey] = useState(false);
  const [showMasterKeyModal, setShowMasterKeyModal] = useState(false);

  // Función separada para verificar el estado de la clave maestra
  const checkMasterKeyStatus = async () => {
    if (!user) return;
    
    try {
      console.log('🔑 Verificando estado de clave maestra...');
      const masterKeyResponse = await masterKeyService.hasMasterKey();
      console.log('🔑 Respuesta clave maestra:', masterKeyResponse);
      
      if (masterKeyResponse.success) {
        setHasMasterKey(masterKeyResponse.hasMasterKey);
        
        // Si el usuario NO tiene clave maestra, mostrar modal
        if (!masterKeyResponse.hasMasterKey) {
          console.log('🔑 Usuario sin clave maestra - mostrando modal');
          setShowMasterKeyModal(true);
        } else {
          console.log('🔑 Usuario ya tiene clave maestra');
          setShowMasterKeyModal(false);
        }
      } else {
        console.warn('🔑 Error verificando clave maestra:', masterKeyResponse.error);
        // En caso de error, asumir que no tiene clave maestra
        setHasMasterKey(false);
        setShowMasterKeyModal(true);
      }
    } catch (error) {
      console.error('🔑 Error en checkMasterKeyStatus:', error);
      // En caso de error de conexión, asumir que no tiene clave maestra
      setHasMasterKey(false);
      setShowMasterKeyModal(true);
    }
  };

  // Verificar estado de autenticación y clave maestra al cargar
  const checkAuth = async () => {
    console.log('🔐 Iniciando verificación de autenticación...');
    setLoading(true);
    
    try {
      const response = await authService.checkAuthStatus();
      console.log('🔐 Respuesta auth:', response);
      
      if (response.success && response.user) {
        console.log('🔐 Usuario autenticado:', response.user);
        setUser(response.user);
        
        // Verificar clave maestra después de confirmar autenticación
        // Usar setTimeout para asegurar que el estado se actualice correctamente
        setTimeout(async () => {
          await checkMasterKeyStatus();
        }, 100);
        
      } else {
        console.log('🔐 Usuario no autenticado');
        setUser(null);
        setHasMasterKey(false);
        setShowMasterKeyModal(false);
      }
    } catch (error) {
      console.error('🔐 Error verificando autenticación:', error);
      setUser(null);
      setHasMasterKey(false);
      setShowMasterKeyModal(false);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    checkAuth();
  }, []);

  // También verificar clave maestra cuando el usuario cambie
  useEffect(() => {
    if (user && !loading) {
      console.log('👤 Usuario cambió, verificando clave maestra...');
      checkMasterKeyStatus();
    }
  }, [user, loading]);

  const login = async (credentials: { email: string; password: string }) => {
    try {
      const response = await authService.login(credentials);
      if (response.success && response.user) {
        console.log('✅ Login exitoso:', response.user);
        setUser(response.user);
        
        // Verificar clave maestra después del login exitoso
        // Usar setTimeout para dar tiempo al estado de actualizarse
        setTimeout(async () => {
          await checkMasterKeyStatus();
        }, 200);
        
        return { success: true };
      } else {
        return { success: false, error: response.error || 'Error en el inicio de sesión' };
      }
    } catch (error) {
      console.error('❌ Error en login del provider:', error);
      return { success: false, error: 'Error de conexión' };
    }
  };

  const register = async (userData: { firstName: string; lastName: string; email: string; password: string }) => {
    try {
      const response = await authService.register(userData);
      if (response.success && response.user) {
        console.log('✅ Registro exitoso:', response.user);
        setUser(response.user);
        
        // Después del registro exitoso, SIEMPRE mostrar modal de clave maestra
        // Los nuevos usuarios nunca tienen clave maestra configurada
        console.log('🆕 Nuevo usuario registrado - configurando para mostrar modal');
        setHasMasterKey(false);
        setShowMasterKeyModal(true);
        
        return { success: true };
      } else {
        return { success: false, error: response.error || 'Error en el registro' };
      }
    } catch (error) {
      console.error('❌ Error en register del provider:', error);
      return { success: false, error: 'Error de conexión' };
    }
  };

  const setupMasterKey = async (masterKey: string): Promise<{ success: boolean; error?: string }> => {
    try {
      console.log('🔑 Configurando clave maestra...');
      const response = await masterKeyService.setMasterKey(masterKey);
      
      if (response.success) {
        console.log('✅ Clave maestra configurada exitosamente');
        setHasMasterKey(true);
        setShowMasterKeyModal(false);
        return { success: true };
      } else {
        console.error('❌ Error configurando clave maestra:', response.error);
        return { success: false, error: response.error || 'Error al configurar la clave maestra' };
      }
    } catch (error) {
      console.error('❌ Error configurando clave maestra:', error);
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
    // Si no tiene clave maestra, no puede cerrar el modal (es obligatorio)
  };

  const logout = async () => {
    console.log('🚪 Cerrando sesión...');
    setLoading(true);
    try {
      await authService.logout();
      setUser(null);
      setHasMasterKey(false);
      setShowMasterKeyModal(false);
      console.log('✅ Sesión cerrada exitosamente');
    } catch (error) {
      console.error('❌ Error al cerrar sesión:', error);
      // Incluso si hay error, limpiar el estado local
      setUser(null);
      setHasMasterKey(false);
      setShowMasterKeyModal(false);
    } finally {
      setLoading(false);
    }
  };

  const value: AuthContextType = {
    user,
    isAuthenticated: !!user,
    hasMasterKey,
    showMasterKeyModal,
    login,
    register,
    logout,
    setupMasterKey,
    closeMasterKeyModal,
    loading,
    checkAuth,
    checkMasterKeyStatus
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
};