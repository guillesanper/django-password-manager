import React, { useState } from 'react';
import { 
  Settings, 
  Key, 
  Shield, 
  FileText, 
  Folder, 
  User,
  ChevronDown
} from 'lucide-react';
// CAMBIO: Usar useUnifiedTheme en lugar de useTheme y ThemedText, ThemedSurface
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
  iconColor: 'indigo' | 'emerald' | 'amber' | 'purple' | 'blue' | 'rose' | 'gray';
}

export const Sidebar: React.FC<SidebarProps> = ({ isOpen, toggleSidebar, currentPage, setCurrentPage }) => {
  const [openMenus, setOpenMenus] = useState<Record<string, boolean>>({});
  const { colors } = useUnifiedTheme(); // CAMBIO: useUnifiedTheme

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
    
    return (
      <button
        onClick={() => {
          setCurrentPage(item.id);
          if (window.innerWidth < 1024) toggleSidebar();
        }}
        className={`sidebar-button ${isActive ? 'active' : ''} ${item.iconColor}`}
      >
        <Icon className={`sidebar-icon ${item.iconColor}`} />
        <span>{item.label}</span>
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
  }> = ({ icon: Icon, label, iconColor, onClick, children }) => {
    return (
      <button 
        onClick={onClick}
        className={`sidebar-button ${iconColor}`}
      >
        <div className="flex items-center">
          <Icon className={`sidebar-icon ${iconColor}`} />
          <span>{label}</span>
        </div>
        {children}
      </button>
    );
  };

  // Componente para elementos de submenú
  const SubMenuItem: React.FC<{ label: string; href: string }> = ({ label, href }) => {
    const [isHovered, setIsHovered] = useState(false);

    return (
      <a 
        href={href}
        className="block px-3 py-2 text-sm rounded-md transition-colors duration-200 ml-8"
        style={{ 
          color: isHovered ? colors.textPrimary : colors.textSecondary,
          backgroundColor: isHovered ? colors.surfaceHover : 'transparent'
        }}
        onMouseEnter={() => setIsHovered(true)}
        onMouseLeave={() => setIsHovered(false)}
      >
        {label}
      </a>
    );
  };

  return (
    <div 
      className={`
        sidebar-container fixed inset-y-0 left-0 z-50 w-64 shadow-lg transform 
        ${isOpen ? 'translate-x-0' : '-translate-x-full'} 
        transition-transform duration-300 ease-in-out 
        lg:translate-x-0 lg:static lg:inset-0 
        themed-scrollbar flex flex-col
      `}
    >
      {/* Brand */}
      <div 
        className="px-6 py-5 border-b"
        style={{ 
          backgroundColor: colors.surface,
          borderBottomColor: colors.border 
        }}
      >
        <div className="flex items-center">
          <Folder className="w-6 h-6 text-indigo-500 mr-3" />
          <h1 
            className="text-lg font-semibold"
            style={{ color: colors.textPrimary }}
          >
            Password Manager
          </h1>
        </div>
      </div>

      {/* Navigation */}
      <nav className="mt-8 px-6 flex-1 overflow-y-auto themed-scrollbar">
        {/* Main Navigation */}
        <div className="sidebar-nav-group">
          {menuItems.map((item) => (
            <MainMenuButton 
              key={item.id} 
              item={item} 
              isActive={currentPage === item.id} 
            />
          ))}
        </div>

        {/* File System Section */}
        <div className="sidebar-nav-group">
          <h3 className="sidebar-group-title">
            Sistema de archivos
          </h3>
          
          <div className="space-y-1">
            <SecondaryMenuButton
              icon={Folder}
              label="Carpetas"
              iconColor="blue"
              onClick={() => toggleMenu('folders')}
            >
              <ChevronDown 
                className={`w-4 h-4 transition-transform duration-200 ${
                  openMenus.folders ? 'rotate-180' : ''
                }`}
                style={{ color: colors.textMuted }}
              />
            </SecondaryMenuButton>
            
            {openMenus.folders && (
              <div className="mt-2 space-y-1">
                <SubMenuItem label="Login" href="#" />
                <SubMenuItem label="Register" href="#" />
                <SubMenuItem label="Forgot Password" href="#" />
              </div>
            )}
          </div>
        </div>

        {/* User & Settings Section */}
        <div className="sidebar-nav-group">
          <h3 className="sidebar-group-title">
            Usuario y ajustes
          </h3>
          
          <div className="space-y-1">
            <SecondaryMenuButton
              icon={User}
              label="Usuario"
              iconColor="rose"
              onClick={() => toggleMenu('user')}
            >
              <ChevronDown 
                className={`w-4 h-4 transition-transform duration-200 ${
                  openMenus.user ? 'rotate-180' : ''
                }`}
                style={{ color: colors.textMuted }}
              />
            </SecondaryMenuButton>
            
            {openMenus.user && (
              <div className="mt-2 space-y-1">
                <SubMenuItem label="Cerrar sesión" href="#" />
                <SubMenuItem label="Configuración de Usuario" href="#" />
              </div>
            )}
            
            <button
              onClick={() => {
                setCurrentPage('settings');
                if (window.innerWidth < 1024) toggleSidebar();
              }}
              className={`sidebar-button ${currentPage === 'settings' ? 'active' : ''} gray`}
            >
              <Settings className="sidebar-icon gray" />
              <span>Ajustes</span>
            </button>
          </div>
        </div>
      </nav>
    </div>
  );
};