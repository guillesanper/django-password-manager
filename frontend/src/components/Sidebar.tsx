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
}

export const Sidebar: React.FC<SidebarProps> = ({ isOpen, toggleSidebar, currentPage, setCurrentPage }) => {
  const [openMenus, setOpenMenus] = useState<Record<string, boolean>>({});

  const toggleMenu = (menuName: string): void => {
    setOpenMenus(prev => ({
      ...prev,
      [menuName]: !prev[menuName]
    }));
  };

  const menuItems: MenuItem[] = [
    { id: 'home', label: 'Inicio', icon: Folder, href: '#' },
    { id: 'passwords', label: 'Ver Contraseñas', icon: Key, href: '#' },
    { id: 'generator', label: 'Generador de contraseñas', icon: Shield, href: '#' },
    { id: 'files', label: 'Encriptación de archivos', icon: FileText, href: '#' }
  ];

  return (
    <div className={`fixed inset-y-0 left-0 z-50 w-64 bg-white border-r border-gray-100 shadow-sm transform ${isOpen ? 'translate-x-0' : '-translate-x-full'} transition-transform duration-300 ease-in-out lg:translate-x-0 lg:static lg:inset-0`}>
      {/* Brand */}
      <div className="flex items-center px-6 py-5 border-b border-gray-50">
        <Folder className="w-6 h-6 text-indigo-500 mr-3" />
        <h1 className="text-lg font-medium text-gray-900">Password Manager</h1>
      </div>

      {/* Navigation */}
      <nav className="mt-8 px-6">
        {/* Main Navigation */}
        <div className="space-y-1">
          {menuItems.map((item, index) => {
            const Icon = item.icon;
            const colorClasses = ['indigo', 'emerald', 'amber', 'purple'];
            const colorClass = colorClasses[index];
            
            return (
              <button
                key={item.id}
                onClick={() => {
                  setCurrentPage(item.id);
                  if (window.innerWidth < 1024) toggleSidebar();
                }}
                className={`sidebar-button ${colorClass} ${
                  currentPage === item.id ? 'active' : ''
                }`}
              >
                <Icon className={`sidebar-icon ${colorClass}`} />
                <span>{item.label}</span>
              </button>
            );
          })}
        </div>

        {/* File System Section */}
        <div className="mt-8 mb-6">
          <h3 className="px-3 text-xs font-medium text-gray-400 uppercase tracking-wide mb-4">
            Sistema de archivos
          </h3>
          
          <div className="space-y-1">
            <button 
              onClick={() => toggleMenu('folders')}
              className="sidebar-button"
            >
              <div className="flex items-center">
                <Folder className="sidebar-icon blue" />
                <span>Carpetas</span>
              </div>
              <ChevronDown className={`w-4 h-4 text-gray-400 transition-transform duration-200 ${openMenus.folders ? 'rotate-180' : ''}`} />
            </button>
            
            {openMenus.folders && (
              <div className="ml-8 mt-2 space-y-1">
                <a href="#" className="block px-3 py-2 text-sm text-gray-500 hover:text-gray-700 hover:bg-gray-50 rounded-md transition-colors duration-150">Login</a>
                <a href="#" className="block px-3 py-2 text-sm text-gray-500 hover:text-gray-700 hover:bg-gray-50 rounded-md transition-colors duration-150">Register</a>
                <a href="#" className="block px-3 py-2 text-sm text-gray-500 hover:text-gray-700 hover:bg-gray-50 rounded-md transition-colors duration-150">Forgot Password</a>
              </div>
            )}
          </div>
        </div>

        {/* User & Settings Section */}
        <div>
          <h3 className="px-3 text-xs font-medium text-gray-400 uppercase tracking-wide mb-4">
            Usuario y ajustes
          </h3>
          
          <div className="space-y-1">
            <button 
              onClick={() => toggleMenu('user')}
              className="sidebar-button"
            >
              <div className="flex items-center">
                <User className="sidebar-icon rose" />
                <span>Usuario</span>
              </div>
              <ChevronDown className={`w-4 h-4 text-gray-400 transition-transform duration-200 ${openMenus.user ? 'rotate-180' : ''}`} />
            </button>
            
            {openMenus.user && (
              <div className="ml-8 mt-2 space-y-1">
                <a href="#" className="block px-3 py-2 text-sm text-gray-500 hover:text-gray-700 hover:bg-gray-50 rounded-md transition-colors duration-150">Cerrar sesión</a>
                <a href="#" className="block px-3 py-2 text-sm text-gray-500 hover:text-gray-700 hover:bg-gray-50 rounded-md transition-colors duration-150">Configuración de Usuario</a>
              </div>
            )}
            
            <button
              onClick={() => {
                setCurrentPage('settings');
                if (window.innerWidth < 1024) toggleSidebar();
              }}
              className={`sidebar-button ${
                currentPage === 'settings' ? 'active' : ''
              }`}
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