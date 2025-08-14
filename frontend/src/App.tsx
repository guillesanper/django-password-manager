import React, { useState, useEffect, useCallback } from 'react'
import { Routes, Route, Navigate, useLocation, useNavigate } from 'react-router-dom'
import { Layout } from './components/Layout'
import { LoginPage } from './pages/LoginPage'
import { RegisterPage } from './pages/RegisterPage'
import { SettingsPage } from './pages/SettingsPage'
import { HomePage } from './pages/HomePage'
import { AuthProvider, useAuth } from './components/AuthProvider'

// Importar el sistema de temas unificado
import { UnifiedThemeProvider } from './theme/UnifiedThemeProvider'

// Importar tipos
import './types/django' // Para los tipos globales de Window

// Mapeo de rutas a pÃ¡ginas para mantener consistencia
const ROUTE_TO_PAGE_MAP: Record<string, string> = {
  '/': 'home',
  '/settings': 'settings',
  '/accounts': 'passwords',
  '/password-generator': 'generator',
  '/file-system': 'files'
}

const PAGE_TO_ROUTE_MAP: Record<string, string> = {
  'home': '/',
  'settings': '/settings',
  'passwords': '/accounts',
  'generator': '/password-generator',
  'files': '/file-system'
}

// Componente separado para el contenido autenticado
const AuthenticatedApp: React.FC = () => {
  const location = useLocation()
  const navigate = useNavigate()
  
  // FunciÃ³n para obtener la pÃ¡gina actual basada en la ruta
  const getCurrentPageFromRoute = useCallback((pathname: string): string => {
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
    
    return 'home' // Valor por defecto
  }, [])
  
  // Estado para la pÃ¡gina actual
  const [currentPage, setCurrentPageState] = useState(() => 
    getCurrentPageFromRoute(location.pathname)
  )
  
  // FunciÃ³n para cambiar la pÃ¡gina que tambiÃ©n actualiza la ruta
  const setCurrentPage = useCallback((page: string) => {
    const route = PAGE_TO_ROUTE_MAP[page]
    if (route && route !== location.pathname) {
      navigate(route)
    }
    setCurrentPageState(page)
  }, [navigate, location.pathname])
  
  // Sincronizar la pÃ¡gina actual cuando cambie la ruta (navegaciÃ³n del navegador)
  useEffect(() => {
    const newPage = getCurrentPageFromRoute(location.pathname)
    if (newPage !== currentPage) {
      setCurrentPageState(newPage)
    }
  }, [location.pathname, currentPage, getCurrentPageFromRoute])

  return (
    <Layout currentPage={currentPage} setCurrentPage={setCurrentPage}>
      <Routes>
        {/* PÃ¡gina principal */}
        <Route 
          path="/" 
          element={<HomePage setCurrentPage={setCurrentPage} />} 
        />
        
        {/* ConfiguraciÃ³n */}
        <Route path="/settings" element={<SettingsPage />} />
        
        {/* Redirigir rutas no encontradas al home */}
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </Layout>
  )
}

// Componente separado para la autenticaciÃ³n
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

// Componente interno que usa el contexto de autenticaciÃ³n
const AppContent: React.FC = () => {
  const { isAuthenticated, loading } = useAuth();

  // Mostrar loading mientras se verifica la autenticaciÃ³n
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
        <AppContent />
      </AuthProvider>
    </UnifiedThemeProvider>
  )
}

export default App