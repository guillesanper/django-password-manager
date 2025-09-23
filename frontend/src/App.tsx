import React, { useState, useEffect, useCallback } from 'react'
import { Routes, Route, Navigate, useLocation, useNavigate, useParams } from 'react-router-dom'
import { Layout } from './components/Layout'
import { LoginPage } from './pages/LoginPage'
import { RegisterPage } from './pages/RegisterPage'
import { SettingsPage } from './pages/SettingsPage'
import { HomePage } from './pages/HomePage'
import { PasswordsPage } from './pages/PasswordPage'
import { PasswordGeneratorPage } from './pages/PasswordGeneratorPage'
import { SecurityPage } from './pages/SecurityPage'
import { FilesPage } from './pages/FilesPages'
import { VaultDetailPage } from './pages/VaultDetailPage'
import { AuthProvider, useAuth } from './components/AuthProvider'
import { AuthErrorProvider } from './components/hooks/AuthErrorProvider' // NUEVA IMPORTACIÓN
import { MasterKeyModal } from './components/MasterKeyModal'

// Importar el sistema de temas unificado
import { UnifiedThemeProvider } from './theme/UnifiedThemeProvider'

// Importar tipos
import './types/django'
import { VaultProvider } from './components/hooks/useVaults'

// Mapeo de rutas a páginas para mantener consistencia
const ROUTE_TO_PAGE_MAP: Record<string, string> = {
  '/': 'home',
  '/settings': 'settings',
  '/accounts': 'passwords',
  '/password-generator': 'generator',
  '/security': 'security',
  '/file-system': 'files',
  '/vault-detail': '/vault-detail'
}

const PAGE_TO_ROUTE_MAP: Record<string, string> = {
  'home': '/',
  'settings': '/settings',
  'passwords': '/accounts',
  'generator': '/password-generator',
  'security': '/security',
  'files': '/file-system',
  'vault-detail': '/vault-detail'
}

// Wrapper para VaultDetailPage que maneja los parámetros de la URL
const VaultDetailPageWrapper: React.FC = () => {
  const { vaultId } = useParams<{ vaultId: string }>()
  const navigate = useNavigate()
  
  const handleBack = useCallback(() => {
    navigate('/accounts')
  }, [navigate])

  if (!vaultId || isNaN(parseInt(vaultId))) {
    return <Navigate to="/accounts" replace />
  }

  return (
    <VaultDetailPage 
      vaultId={parseInt(vaultId)} 
      onBack={handleBack} 
    />
  )
}

// Componente separado para el contenido autenticado
const AuthenticatedApp: React.FC = () => {
  const location = useLocation()
  const navigate = useNavigate()
  const { showMasterKeyModal, setupMasterKey, closeMasterKeyModal, user } = useAuth()
  
  // Función para obtener la página actual basada en la ruta
  const getCurrentPageFromRoute = useCallback((pathname: string): string => {
    // Verificar si es una ruta de vault específica
    if (pathname.startsWith('/vault/')) {
      return 'vault-detail'
    }
    
    // Buscar coincidencia exacta primero
    if (ROUTE_TO_PAGE_MAP[pathname]) {
      return ROUTE_TO_PAGE_MAP[pathname]
    }
    
    // Buscar coincidencia por prefijo para rutas anidadas
    for (const [route, page] of Object.entries(ROUTE_TO_PAGE_MAP)) {
      if (pathname.startsWith(route) && route !== '/') {
        return page
      }
    }
    
    return 'home'
  }, [])
  
  // Estado para la página actual
  const [currentPage, setCurrentPageState] = useState(() => 
    getCurrentPageFromRoute(location.pathname)
  )
  
  // Función para cambiar la página que también actualiza la ruta
  const setCurrentPage = useCallback((page: string) => {
    const route = PAGE_TO_ROUTE_MAP[page]
    if (route && route !== location.pathname) {
      navigate(route)
    }
    setCurrentPageState(page)
  }, [navigate, location.pathname])

  // Función para navegar a un vault específico
  const handleNavigateToVault = useCallback((vaultId: number) => {
    navigate(`/vault/${vaultId}`)
    setCurrentPageState('vault-detail')
  }, [navigate])
  
  // Sincronizar la página actual cuando cambie la ruta
  useEffect(() => {
    const newPage = getCurrentPageFromRoute(location.pathname)
    if (newPage !== currentPage) {
      setCurrentPageState(newPage)
    }
  }, [location.pathname, currentPage, getCurrentPageFromRoute])

  // Handler para configurar la clave maestra
  const handleSetupMasterKey = useCallback(async (masterKey: string) => {
    try {
      const result = await setupMasterKey(masterKey)
      
      if (result.success) {
        return { success: true }
      } else {
        return { success: false, error: result.error || 'Error al configurar la clave maestra' }
      }
    } catch (error) {
      console.error('Error setting up master key:', error)
      return { success: false, error: 'Error de conexión' }
    }
  }, [setupMasterKey])

  return (
    <>
      <Layout 
        currentPage={currentPage} 
        setCurrentPage={setCurrentPage}
        onNavigateToVault={handleNavigateToVault}
      >
        <Routes>
          <Route 
            path="/" 
            element={<HomePage setCurrentPage={setCurrentPage} />} 
          />
          
          <Route 
            path="/accounts" 
            element={<PasswordsPage />} 
          />
          
          <Route 
            path="/password-generator" 
            element={<PasswordGeneratorPage />} 
          />

          <Route 
            path="/security" 
            element={<SecurityPage />} 
          />

          <Route 
            path="/file-system" 
            element={<FilesPage />} 
          />

          <Route 
            path="/vault/:vaultId" 
            element={<VaultDetailPageWrapper />} 
          />
          
          <Route path="/settings" element={<SettingsPage />} />
          
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </Layout>

      {showMasterKeyModal && (
        <MasterKeyModal
          isOpen={showMasterKeyModal}
          onClose={closeMasterKeyModal}
          onSubmit={handleSetupMasterKey}
          userName={user?.firstName || 'Usuario'}
        />
      )}
    </>
  )
}

// Componente separado para la autenticación
const AuthApp: React.FC = () => {
  const navigate = useNavigate();

  const handleSwitchToRegister = () => {
    navigate('/register');
  };

  const handleSwitchToLogin = () => {
    navigate('/login');
  };

  return (
    <Routes>
      <Route 
        path="/login" 
        element={
          <LoginPage 
            onSwitchToRegister={handleSwitchToRegister}
          />
        } 
      />
      
      <Route 
        path="/register" 
        element={
          <RegisterPage 
            onSwitchToLogin={handleSwitchToLogin}
          />
        } 
      />
      <Route path="*" element={<Navigate to="/login" replace />} />
    </Routes>
  )
}

// Componente interno que usa el contexto de autenticación
const AppContent: React.FC = () => {
  const { isAuthenticated, loading } = useAuth();

  // Mostrar loading mientras se verifica la autenticación
  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-[var(--color-background)]">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-[var(--color-primary)] mx-auto mb-4"></div>
          <p className="text-[var(--color-text-secondary)]">Cargando...</p>
        </div>
      </div>
    );
  }

  return isAuthenticated ? <AuthenticatedApp /> : <AuthApp />;
};

function App() {
  return (
    <UnifiedThemeProvider>
      <AuthProvider>
        <AuthErrorProvider> {/* NUEVO PROVIDER AQUÍ */}
          <VaultProvider> 
            <AppContent />
          </VaultProvider>
        </AuthErrorProvider>
      </AuthProvider>
    </UnifiedThemeProvider>
  )
}

export default App