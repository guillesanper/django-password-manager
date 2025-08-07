// frontend/src/App.tsx
import React, { useState, useEffect, useCallback } from 'react'
import { Routes, Route, Navigate, useLocation, useNavigate } from 'react-router-dom'
import { Layout } from './components/Layout'
//import LoginPage from './pages/LoginPage'
//import RegisterPage from './pages/RegisterPage'
//import AccountsPage from './pages/AccountsPage'
//import GeneratorPage from './pages/GeneratorPage'
//import FilesPage from './pages/FilesPage'
import { SettingsPage } from './pages/SettingsPage'
import { HomePage } from './pages/HomePage'

// Importar tipos
import './types/django' // Para los tipos globales de Window

// Mapeo de rutas a páginas para mantener consistencia
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

function App() {
  const location = useLocation()
  const navigate = useNavigate()
  
  // Función para obtener la página actual basada en la ruta
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
  
  // Sincronizar la página actual cuando cambie la ruta (navegación del navegador)
  useEffect(() => {
    const newPage = getCurrentPageFromRoute(location.pathname)
    if (newPage !== currentPage) {
      setCurrentPageState(newPage)
    }
  }, [location.pathname, currentPage, getCurrentPageFromRoute])
  
  // Verificar si el usuario está autenticado basado en los datos de Django
  // Corregir el nombre de la propiedad global (era djangoData, debería ser DjangoData)
  //const isAuthenticated = window.DjangoData?.user?.isAuthenticated || false
  const isAuthenticated = true;
  
  // Si no está autenticado, mostrar solo las rutas públicas (login/register)
  if (!isAuthenticated) {
    return (
      <Routes>
        {/* Páginas comentadas temporalmente hasta que se implementen */}
        {/* <Route path="/login" element={<LoginPage />} /> */}
        {/* <Route path="/register" element={<RegisterPage />} /> */}
        
        {/* Mientras tanto, redirigir a home para desarrollo */}
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    )
  }

  // Si está autenticado, mostrar la aplicación completa con Layout
  return (
    <Layout currentPage={currentPage} setCurrentPage={setCurrentPage}>
      <Routes>
        {/* Página principal */}
        <Route 
          path="/" 
          element={<HomePage setCurrentPage={setCurrentPage} />} 
        />
        
        {/* Gestión de cuentas/passwords - comentado hasta implementar */}
        {/* <Route path="/accounts/*" element={<AccountsPage />} /> */}
        
        {/* Generador de contraseñas - comentado hasta implementar */}
        {/* <Route path="/password-generator/*" element={<GeneratorPage />} /> */}
        
        {/* Sistema de archivos - comentado hasta implementar */}
        {/* <Route path="/file-system/*" element={<FilesPage />} /> */}
        
        {/* Configuración */}
        <Route path="/settings" element={<SettingsPage />} />
        
        {/* Redirigir rutas no encontradas al home */}
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </Layout>
  )
}

export default App