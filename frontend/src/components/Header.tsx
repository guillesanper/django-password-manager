// components/Header.tsx
import React, { useState } from 'react';
import { 
  Settings,  
  User, 
  Bell, 
  Mail, 
  Search,
  Menu,
  LogOut,
  ChevronDown
} from 'lucide-react';
import { useAuth } from './AuthProvider'; // Importar el contexto de autenticación
import { useUnifiedTheme } from './UnifiedThemeProvider'; // CAMBIO: useUnifiedTheme

export interface HeaderProps {
  toggleSidebar: () => void;
  userName?: string;
}

export const Header: React.FC<HeaderProps> = ({ toggleSidebar, userName }) => {
  const { user, logout } = useAuth();
  const { colors } = useUnifiedTheme(); // CAMBIO: useUnifiedTheme
  const [showUserMenu, setShowUserMenu] = useState<boolean>(false);
  
  // Usar el nombre del usuario autenticado o el prop como fallback
  const displayName = user ? `${user.firstName} ${user.lastName}`.trim() || user.username : userName || 'Usuario';

  const handleLogout = async () => {
    setShowUserMenu(false);
    await logout();
  };

  const handleSettingsClick = () => {
    setShowUserMenu(true);
    // Aquí puedes agregar navegación a settings si necesitas
    window.location.href = '/settings';
  };

  return (
    <header 
      className="shadow-sm border-b"
      style={{ 
        backgroundColor: colors.headerBg,
        borderColor: colors.headerBorder 
      }}
    >
      <div className="flex items-center justify-between px-6 py-3">
        {/* Mobile menu button */}
        <button
          onClick={toggleSidebar}
          className="lg:hidden p-1 rounded-md transition-colors"
          style={{ 
            color: colors.headerText,
            backgroundColor: 'transparent'
          }}
          onMouseEnter={(e) => {
            e.currentTarget.style.backgroundColor = colors.sidebarHover;
          }}
          onMouseLeave={(e) => {
            e.currentTarget.style.backgroundColor = 'transparent';
          }}
        >
          <Menu className="w-6 h-6" />
        </button>

        {/* Logo/Título */}
        <div className="flex items-center space-x-3">
          <div className="w-8 h-8 bg-gradient-to-r from-indigo-500 to-purple-600 rounded-lg flex items-center justify-center">
            <span className="text-white font-bold text-sm">PM</span>
          </div>
          <h1 className="text-xl font-semibold hidden sm:block" style={{ color: colors.headerText }}>
            Password Manager
          </h1>
        </div>

        {/* Search Bar */}
        <div className="hidden md:flex flex-1 max-w-lg mx-6">
          <div className="relative w-full">
            <input
              type="text"
              placeholder="Buscar..."
              className="w-full pl-10 pr-4 py-2.5 rounded-lg transition-colors focus:outline-none focus:ring-2 focus:border-transparent"
              style={{ 
                backgroundColor: colors.surface,
                borderColor: colors.border,
                color: colors.textPrimary,
                borderWidth: '1px',
                borderStyle: 'solid'
              }}
              onFocus={(e) => {
                e.currentTarget.style.borderColor = 'transparent';
                e.currentTarget.style.boxShadow = `0 0 0 2px ${colors.primary}`;
              }}
              onBlur={(e) => {
                e.currentTarget.style.borderColor = colors.border;
                e.currentTarget.style.boxShadow = 'none';
              }}
            />
            <Search 
              className="absolute left-3 top-3 w-5 h-5" 
              style={{ color: colors.textMuted }}
            />
          </div>
        </div>

        {/* Right side icons */}
        <div className="flex items-center gap-x-6">
          {/* Notifications */}
          <button 
            className="relative p-2 rounded-lg transition-colors"
            style={{ 
              color: colors.headerText,
              backgroundColor: 'transparent'
            }}
            onMouseEnter={(e) => {
              e.currentTarget.style.backgroundColor = colors.sidebarHover;
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.backgroundColor = 'transparent';
            }}
          >
            <Bell className="w-5 h-5" />
            <span 
              className="absolute -top-1 -right-1 text-white text-xs rounded-full h-4 w-4 flex items-center justify-center font-medium"
              style={{ backgroundColor: colors.error }}
            >
              3
            </span>
          </button>

          {/* Messages */}
          <button 
            className="relative p-2 rounded-lg transition-colors"
            style={{ 
              color: colors.headerText,
              backgroundColor: 'transparent'
            }}
            onMouseEnter={(e) => {
              e.currentTarget.style.backgroundColor = colors.sidebarHover;
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.backgroundColor = 'transparent';
            }}
          >
            <Mail className="w-5 h-5" />
            <span 
              className="absolute -top-1 -right-1 text-white text-xs rounded-full h-4 w-4 flex items-center justify-center font-medium"
              style={{ backgroundColor: colors.error }}
            >
              7
            </span>
          </button>

          {/* User Menu */}
          <div className="relative">
            <button
              onClick={() => setShowUserMenu(!showUserMenu)}
              className="flex items-center p-2 rounded-lg transition-colors"
              style={{ 
                color: colors.headerText,
                backgroundColor: 'transparent'
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.backgroundColor = colors.sidebarHover;
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.backgroundColor = 'transparent';
              }}
            >
              <div className="flex items-center space-x-3">
                <div 
                  className="w-8 h-8 rounded-full flex items-center justify-center"
                  style={{ backgroundColor: colors.primary || '#6366f1' }}
                >
                  <User className="w-4 h-4 text-white" />
                </div>
                <div className="text-left hidden sm:block">
                  <div className="text-sm font-medium" style={{ color: colors.headerText }}>
                    {displayName}
                  </div>
                  <div 
                    className="text-xs"
                    style={{ color: colors.textMuted }}
                  >
                    {user?.email || 'usuario@example.com'}
                  </div>
                </div>
                <ChevronDown 
                  className={`w-4 h-4 transition-transform ${showUserMenu ? 'rotate-180' : ''}`}
                  style={{ color: colors.textMuted }}
                />
              </div>
            </button>

            {showUserMenu && (
              <>
                {/* Overlay para cerrar el dropdown */}
                <div 
                  className="fixed inset-0 z-10"
                  onClick={() => setShowUserMenu(false)}
                />
                
                {/* Contenido del dropdown */}
                <div 
                  className="absolute right-0 mt-2 w-48 rounded-lg shadow-lg border z-50"
                  style={{ 
                    backgroundColor: colors.surface,
                    borderColor: colors.border 
                  }}
                >
                  <div className="py-1">
                    <div 
                      className="px-4 py-2 text-sm border-b"
                      style={{ 
                        color: colors.textMuted,
                        borderColor: colors.border
                      }}
                    >
                      Sesión iniciada como
                      <div 
                        className="font-medium"
                        style={{ color: colors.textPrimary }}
                      >
                        {displayName}
                      </div>
                    </div>
                    
                    <button
                      onClick={handleSettingsClick}
                      className="w-full px-4 py-2 text-sm text-left flex items-center space-x-2 hover:bg-opacity-50 transition-colors"
                      style={{ 
                        color: colors.textPrimary,
                        backgroundColor: 'transparent'
                      }}
                      onMouseEnter={(e) => {
                        e.currentTarget.style.backgroundColor = colors.surfaceHover || colors.sidebarHover;
                      }}
                      onMouseLeave={(e) => {
                        e.currentTarget.style.backgroundColor = 'transparent';
                      }}
                    >
                      <Settings 
                        className="w-4 h-4" 
                        style={{ color: colors.textMuted }}
                      />
                      <span>Configuración</span>
                    </button>

                    <div 
                      className="border-t my-1"
                      style={{ borderColor: colors.border }}
                    ></div>
                    
                    <button
                      onClick={handleLogout}
                      className="w-full px-4 py-2 text-sm text-left flex items-center space-x-2 hover:bg-opacity-50 transition-colors"
                      style={{ 
                        color: colors.textPrimary,
                        backgroundColor: 'transparent'
                      }}
                      onMouseEnter={(e) => {
                        e.currentTarget.style.backgroundColor = colors.surfaceHover || colors.sidebarHover;
                      }}
                      onMouseLeave={(e) => {
                        e.currentTarget.style.backgroundColor = 'transparent';
                      }}
                    >
                      <LogOut 
                        className="w-4 h-4" 
                        style={{ color: colors.textMuted }}
                      />
                      <span>Cerrar Sesión</span>
                    </button>
                  </div>
                </div>
              </>
            )}
          </div>
        </div>
      </div>
    </header>
  );
};