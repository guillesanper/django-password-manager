import React, { useState, useEffect, useRef } from 'react';
import { 
  Settings, 
  Key, 
  Shield, 
  FileText, 
  Folder, 
  User,
  ChevronDown,
  X,
  AlertTriangle // Agregado para el icono de seguridad
} from 'lucide-react';
import { useUnifiedTheme } from '../theme/UnifiedThemeProvider';

export interface SidebarProps {
  isOpen: boolean;
  toggleSidebar: () => void;
  currentPage: string;
  setCurrentPage: (page: string) => void;
}

interface MenuItem {
  id: string;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  href: string;
  iconColor: 'indigo' | 'emerald' | 'amber' | 'purple' | 'blue' | 'rose' | 'gray' | 'red'; // Agregado 'red'
}

export const Sidebar: React.FC<SidebarProps> = ({ isOpen, toggleSidebar, currentPage, setCurrentPage }) => {
  const [openMenus, setOpenMenus] = useState<Record<string, boolean>>({});
  const [isMobile, setIsMobile] = useState<boolean>(false);
  const sidebarRef = useRef<HTMLDivElement>(null);
  const { colors } = useUnifiedTheme();

  // Detectar si es móvil
  useEffect(() => {
    const checkIsMobile = () => {
      setIsMobile(window.innerWidth < 1024);
    };

    checkIsMobile();
    window.addEventListener('resize', checkIsMobile);
    return () => window.removeEventListener('resize', checkIsMobile);
  }, []);

  // Cerrar sidebar en móvil cuando se hace clic fuera
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (
        isMobile && 
        isOpen && 
        sidebarRef.current && 
        !sidebarRef.current.contains(event.target as Node)
      ) {
        toggleSidebar();
      }
    };

    if (isMobile && isOpen) {
      document.addEventListener('mousedown', handleClickOutside);
      // Prevenir scroll del body cuando el sidebar está abierto en móvil
      document.body.style.overflow = 'hidden';
    } else {
      document.body.style.overflow = 'unset';
    }

    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
      document.body.style.overflow = 'unset';
    };
  }, [isMobile, isOpen, toggleSidebar]);

  // Cerrar sidebar en móvil con tecla Escape
  useEffect(() => {
    const handleEscape = (event: KeyboardEvent) => {
      if (event.key === 'Escape' && isMobile && isOpen) {
        toggleSidebar();
      }
    };

    document.addEventListener('keydown', handleEscape);
    return () => document.removeEventListener('keydown', handleEscape);
  }, [isMobile, isOpen, toggleSidebar]);

  const toggleMenu = (menuName: string): void => {
    setOpenMenus(prev => ({
      ...prev,
      [menuName]: !prev[menuName]
    }));
  };

  const menuItems: MenuItem[] = [
    { 
      id: 'home', 
      label: 'Inicio', 
      icon: Folder, 
      href: '#',
      iconColor: 'indigo'
    },
    { 
      id: 'passwords', 
      label: 'Ver Contraseñas', 
      icon: Key, 
      href: '#',
      iconColor: 'emerald'
    },
    { 
      id: 'generator', 
      label: 'Generador de contraseñas', 
      icon: Shield, 
      href: '#',
      iconColor: 'amber'
    },
    { 
      id: 'security', 
      label: 'Vigilancia de Seguridad', 
      icon: AlertTriangle, 
      href: '#',
      iconColor: 'red'
    },
    { 
      id: 'files', 
      label: 'Encriptación de archivos', 
      icon: FileText, 
      href: '#',
      iconColor: 'purple'
    }
  ];

  // Componente para botones del menú principal
  const MainMenuButton: React.FC<{ item: MenuItem; isActive: boolean }> = ({ item, isActive }) => {
    const Icon = item.icon;
    
    const handleClick = () => {
      setCurrentPage(item.id);
      // Cerrar sidebar en móvil después de seleccionar
      if (isMobile) {
        toggleSidebar();
      }
    };
    
    return (
      <button
        onClick={handleClick}
        className={`sidebar-button ${isActive ? 'active' : ''} ${item.iconColor}`}
        aria-label={item.label}
        role="menuitem"
      >
        <Icon className={`sidebar-icon ${item.iconColor}`} />
        <span className="sidebar-button-text">{item.label}</span>
      </button>
    );
  };

  // Componente para botones del menú secundario
  const SecondaryMenuButton: React.FC<{ 
    icon: React.ComponentType<{ className?: string }>;
    label: string;
    iconColor: 'blue' | 'rose' | 'gray';
    onClick: () => void;
    children?: React.ReactNode;
    isExpanded?: boolean;
  }> = ({ icon: Icon, label, iconColor, onClick, children, isExpanded = false }) => {
    return (
      <button 
        onClick={onClick}
        className={`sidebar-button ${iconColor}`}
        aria-expanded={isExpanded}
        aria-label={`${label} ${isExpanded ? 'contraer' : 'expandir'}`}
        role="menuitem"
      >
        <div className="flex items-center w-full">
          <Icon className={`sidebar-icon ${iconColor}`} />
          <span className="sidebar-button-text flex-1 text-left">{label}</span>
          {children}
        </div>
      </button>
    );
  };

  // Componente para elementos de submenú
  const SubMenuItem: React.FC<{ label: string; href: string }> = ({ label, href }) => {
    const [isHovered, setIsHovered] = useState(false);

    return (
      <a 
        href={href}
        className="block px-3 py-2 text-sm rounded-md transition-colors duration-200 ml-8 sidebar-submenu-item"
        style={{ 
          color: isHovered ? colors.textPrimary : colors.textSecondary,
          backgroundColor: isHovered ? colors.surfaceHover : 'transparent'
        }}
        onMouseEnter={() => setIsHovered(true)}
        onMouseLeave={() => setIsHovered(false)}
        role="menuitem"
      >
        {label}
      </a>
    );
  };

  const handleSettingsClick = () => {
    setCurrentPage('settings');
    if (isMobile) {
      toggleSidebar();
    }
  };

  return (
    <>
      {/* Overlay para móvil */}
      {isMobile && isOpen && (
        <div 
          className="fixed inset-0 bg-black bg-opacity-50 z-40 lg:hidden transition-opacity duration-300"
          onClick={toggleSidebar}
          aria-hidden="true"
        />
      )}

      {/* Sidebar */}
      <div 
        ref={sidebarRef}
        className={`
          sidebar-container fixed inset-y-0 left-0 z-50 w-64 shadow-lg transform 
          ${isOpen ? 'translate-x-0' : '-translate-x-full'} 
          transition-transform duration-300 ease-in-out 
          lg:translate-x-0 lg:static lg:inset-0 lg:z-auto
          themed-scrollbar flex flex-col
        `}
        role="navigation"
        aria-label="Navegación principal"
      >
        {/* Header del sidebar con botón de cierre en móvil */}
        <div 
          className="px-6 py-5 border-b relative"
          style={{ 
            backgroundColor: colors.surface,
            borderBottomColor: colors.border 
          }}
        >
          <div className="flex items-center justify-between">
            <div className="flex items-center">
              <Folder className="w-6 h-6 text-indigo-500 mr-3" />
              <h1 
                className="text-lg font-semibold"
                style={{ color: colors.textPrimary }}
              >
                Password Manager
              </h1>
            </div>
            
            {/* Botón de cierre solo en móvil */}
            {isMobile && (
              <button
                onClick={toggleSidebar}
                className="p-2 rounded-lg transition-colors lg:hidden"
                style={{ 
                  color: colors.textMuted,
                  backgroundColor: 'transparent'
                }}
                onMouseEnter={(e) => {
                  e.currentTarget.style.backgroundColor = colors.surfaceHover;
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.backgroundColor = 'transparent';
                }}
                aria-label="Cerrar menú"
              >
                <X className="w-5 h-5" />
              </button>
            )}
          </div>
        </div>

        {/* Navigation */}
        <nav 
          className="mt-8 px-6 flex-1 overflow-y-auto themed-scrollbar"
          role="menu"
          aria-label="Menú de navegación"
        >
          {/* Main Navigation */}
          <div className="sidebar-nav-group" role="group" aria-label="Navegación principal">
            {menuItems.map((item) => (
              <MainMenuButton 
                key={item.id} 
                item={item} 
                isActive={currentPage === item.id} 
              />
            ))}
          </div>

          {/* File System Section */}
          <div className="sidebar-nav-group" role="group" aria-label="Sistema de archivos">
            <h3 className="sidebar-group-title">
              Sistema de archivos
            </h3>
            
            <div className="space-y-1">
              <SecondaryMenuButton
                icon={Folder}
                label="Carpetas"
                iconColor="blue"
                onClick={() => toggleMenu('folders')}
                isExpanded={openMenus.folders}
              >
                <ChevronDown 
                  className={`w-4 h-4 transition-transform duration-200 ${
                    openMenus.folders ? 'rotate-180' : ''
                  }`}
                  style={{ color: colors.textMuted }}
                />
              </SecondaryMenuButton>
              
              {openMenus.folders && (
                <div 
                  className="mt-2 space-y-1 sidebar-submenu"
                  role="menu"
                  aria-label="Submenu de carpetas"
                >
                  <SubMenuItem label="Login" href="#" />
                  <SubMenuItem label="Register" href="#" />
                  <SubMenuItem label="Forgot Password" href="#" />
                </div>
              )}
            </div>
          </div>

          {/* User & Settings Section */}
          <div className="sidebar-nav-group" role="group" aria-label="Usuario y ajustes">
            <h3 className="sidebar-group-title">
              Usuario y ajustes
            </h3>
            
            <div className="space-y-1">
              <SecondaryMenuButton
                icon={User}
                label="Usuario"
                iconColor="rose"
                onClick={() => toggleMenu('user')}
                isExpanded={openMenus.user}
              >
                <ChevronDown 
                  className={`w-4 h-4 transition-transform duration-200 ${
                    openMenus.user ? 'rotate-180' : ''
                  }`}
                  style={{ color: colors.textMuted }}
                />
              </SecondaryMenuButton>
              
              {openMenus.user && (
                <div 
                  className="mt-2 space-y-1 sidebar-submenu"
                  role="menu"
                  aria-label="Submenu de usuario"
                >
                  <SubMenuItem label="Cerrar sesión" href="#" />
                  <SubMenuItem label="Configuración de Usuario" href="#" />
                </div>
              )}
              
              <button
                onClick={handleSettingsClick}
                className={`sidebar-button ${currentPage === 'settings' ? 'active' : ''} gray`}
                role="menuitem"
                aria-label="Ajustes"
              >
                <Settings className="sidebar-icon gray" />
                <span className="sidebar-button-text">Ajustes</span>
              </button>
            </div>
          </div>
        </nav>

        {/* Footer del sidebar - solo en escritorio */}
        <div 
          className="hidden lg:block p-4 border-t"
          style={{ 
            backgroundColor: colors.backgroundSecondary,
            borderTopColor: colors.border 
          }}
        >
          <div className="text-xs text-center" style={{ color: colors.textMuted }}>
            v1.0.0 - Password Manager
          </div>
        </div>
      </div>
    </>
  );
};