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
  AlertTriangle,
  Lock,
  Plus,
  MoreVertical,
  Edit3,
  Trash2
} from 'lucide-react';
import { useUnifiedTheme } from './UnifiedThemeProvider';
import { useVaults } from './hooks/useVaults';
import { CreateVaultModal } from './vaults/CreateVaultModal';
import { ManageVaultModal } from './vaults/ManageVaultModal';
import type { Vault } from '../services/vaultService';

export interface SidebarProps {
  isOpen: boolean;
  toggleSidebar: () => void;
  currentPage: string;
  setCurrentPage: (page: string) => void;
  onNavigateToVault?: (vaultId: number) => void;
}

interface MenuItem {
  id: string;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  href: string;
  iconColor: 'indigo' | 'emerald' | 'amber' | 'purple' | 'blue' | 'rose' | 'gray' | 'red';
}

// Colores de vaults
export const VAULT_COLORS = {
  blue: {
    bg: 'bg-blue-100',
    icon: 'text-blue-600',
    hover: 'hover:bg-blue-50',
    border: 'border-blue-200',
    color: '#3b82f6',
    hoverBg: 'rgba(59, 130, 246, 0.1)'
  },
  green: {
    bg: 'bg-green-100', 
    icon: 'text-green-600',
    hover: 'hover:bg-green-50',
    border: 'border-green-200',
    color: '#10b981',
    hoverBg: 'rgba(16, 185, 129, 0.1)'
  },
  purple: {
    bg: 'bg-purple-100',
    icon: 'text-purple-600', 
    hover: 'hover:bg-purple-50',
    border: 'border-purple-200',
    color: '#8b5cf6',
    hoverBg: 'rgba(139, 92, 246, 0.1)'
  },
  pink: {
    bg: 'bg-pink-100',
    icon: 'text-pink-600',
    hover: 'hover:bg-pink-50', 
    border: 'border-pink-200',
    color: '#ec4899',
    hoverBg: 'rgba(236, 72, 153, 0.1)'
  },
  yellow: {
    bg: 'bg-yellow-100',
    icon: 'text-yellow-600',
    hover: 'hover:bg-yellow-50',
    border: 'border-yellow-200',
    color: '#f59e0b',
    hoverBg: 'rgba(245, 158, 11, 0.1)'
  },
  red: {
    bg: 'bg-red-100',
    icon: 'text-red-600',
    hover: 'hover:bg-red-50',
    border: 'border-red-200',
    color: '#ef4444',
    hoverBg: 'rgba(239, 68, 68, 0.1)'
  },
  gray: {
    bg: 'bg-gray-100',
    icon: 'text-gray-600',
    hover: 'hover:bg-gray-50',
    border: 'border-gray-200',
    color: '#6b7280',
    hoverBg: 'rgba(107, 114, 128, 0.1)'
  }
};

export const Sidebar: React.FC<SidebarProps> = ({ 
  isOpen, 
  toggleSidebar, 
  currentPage, 
  setCurrentPage, 
  onNavigateToVault 
}) => {
  const [openMenus, setOpenMenus] = useState<Record<string, boolean>>({});
  const [isMobile, setIsMobile] = useState<boolean>(false);
  const [activeVaultActions, setActiveVaultActions] = useState<number | null>(null);
  const [showCreateVault, setShowCreateVault] = useState(false);
  const [showManageVault, setShowManageVault] = useState(false);
  const [vaultToManage, setVaultToManage] = useState<Vault | null>(null);
  
  const sidebarRef = useRef<HTMLDivElement>(null);
  const { colors } = useUnifiedTheme();
  const { 
    vaults, 
    loading, 
    createVault,
  } = useVaults();

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
      document.body.style.overflow = 'hidden';
    } else {
      document.body.style.overflow = 'unset';
    }

    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
      document.body.style.overflow = 'unset';
    };
  }, [isMobile, isOpen, toggleSidebar]);

  // Cerrar menús de acciones cuando se hace clic fuera
  useEffect(() => {
    const handleClickOutside = () => {
      if (activeVaultActions !== null) {
        setActiveVaultActions(null);
      }
    };

    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, [activeVaultActions]);

  // Cerrar sidebar en móvil con tecla Escape
  useEffect(() => {
    const handleEscape = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        if (isMobile && isOpen) {
          toggleSidebar();
        }
        if (activeVaultActions !== null) {
          setActiveVaultActions(null);
        }
      }
    };

    document.addEventListener('keydown', handleEscape);
    return () => document.removeEventListener('keydown', handleEscape);
  }, [isMobile, isOpen, toggleSidebar, activeVaultActions]);

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

  // Handlers para vault actions
  const handleCreateVault = async (vaultData: any) => {
    try {
      const result = await createVault(vaultData);
      if (result.success) {
        setShowCreateVault(false);
        return result;
      }
      throw new Error(result.message || 'Error al crear el vault');
    } catch (error) {
      throw error;
    }
  };

  const handleEditVault = (vault: Vault) => {
    setVaultToManage(vault);
    setShowManageVault(true);
    setActiveVaultActions(null);
  };

  const handleDeleteVault = async (vault: Vault) => {
    // Aquí podrías mostrar un modal de confirmación
    console.log('Delete vault:', vault);
    setActiveVaultActions(null);
  };

  const handleViewVault = (vault: Vault) => {
    // Usar la nueva función de navegación si está disponible
    if (onNavigateToVault) {
      onNavigateToVault(vault.id);
    } else {
      // Fallback: cambiar página a vault específico (método anterior)
      setCurrentPage(`vault-${vault.id}`);
    }
    setActiveVaultActions(null);
    if (isMobile) {
      toggleSidebar();
    }
  };

  // Componente para botones del menú principal
  const MainMenuButton: React.FC<{ item: MenuItem; isActive: boolean }> = ({ item, isActive }) => {
    const Icon = item.icon;
    
    const handleClick = () => {
      setCurrentPage(item.id);
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

  // Componente para vault items - CORREGIDO
  const VaultItem: React.FC<{ vault: Vault }> = ({ vault }) => {
    const colorScheme = VAULT_COLORS[vault.color as keyof typeof VAULT_COLORS] || VAULT_COLORS.blue;
    const [isHovered, setIsHovered] = useState(false);
    const isActive = currentPage.startsWith('vault-') && currentPage.includes(vault.id.toString());
    const showActions = activeVaultActions === vault.id;
    
    const handleVaultClick = (e: React.MouseEvent) => {
      // Prevenir propagación si se hace clic en el botón de acciones
      if ((e.target as HTMLElement).closest('[data-vault-actions]')) {
        return;
      }
      handleViewVault(vault);
    };

    const handleActionsClick = (e: React.MouseEvent) => {
      e.stopPropagation();
      setActiveVaultActions(showActions ? null : vault.id);
    };

    return (
      <div
        className="relative"
        onMouseEnter={() => setIsHovered(true)}
        onMouseLeave={() => setIsHovered(false)}
      >
        {/* Usar div clickeable en lugar de button para evitar anidamiento */}
        <div
          onClick={handleVaultClick}
          className={`
            w-full flex items-center justify-between p-3 rounded-lg transition-all duration-200 cursor-pointer
            ${isActive ? 'font-semibold' : 'font-medium'}
          `}
          style={{
            backgroundColor: isHovered || isActive
              ? colorScheme.hoverBg
              : 'transparent',
            color: colors.textPrimary,
            border: isActive 
              ? `2px solid ${colorScheme.color}`
              : '2px solid transparent'
          }}
          role="button"
          tabIndex={0}
          onKeyDown={(e) => {
            if (e.key === 'Enter' || e.key === ' ') {
              e.preventDefault();
              handleViewVault(vault);
            }
          }}
          aria-label={`Abrir vault ${vault.name}`}
        >
          <div className="flex items-center space-x-3">
            <div 
              className="w-6 h-6 rounded-full flex items-center justify-center flex-shrink-0"
              style={{ backgroundColor: colorScheme.color }}
            >
              {vault.is_private ? (
                <Lock className="w-3 h-3 text-white" />
              ) : (
                <Folder className="w-3 h-3 text-white" />
              )}
            </div>
            <div className="text-left min-w-0 flex-1">
              <div 
                className="text-sm truncate"
                style={{ color: colors.textPrimary }}
              >
                {vault.name}
              </div>
              <div 
                className="text-xs"
                style={{ color: colors.textMuted }}
              >
                {vault.password_count || 0} contraseñas
              </div>
            </div>
          </div>
          
          {/* Botón de acciones separado */}
          {(isHovered || showActions) && (
            <button
              onClick={handleActionsClick}
              className="p-1 rounded hover:bg-black hover:bg-opacity-5 transition-colors"
              style={{ color: colors.textMuted }}
              data-vault-actions="true"
              aria-label="Opciones del vault"
            >
              <MoreVertical className="w-4 h-4" />
            </button>
          )}
        </div>

        {/* Menú de acciones del vault */}
        {showActions && (
          <div 
            className="absolute right-0 top-full mt-1 w-48 rounded-lg shadow-lg border z-50"
            style={{ 
              backgroundColor: colors.surface,
              borderColor: colors.border 
            }}
            onClick={(e) => e.stopPropagation()}
          >
            <div className="py-1">
              <button 
                onClick={() => handleEditVault(vault)}
                className="w-full text-left px-4 py-2 text-sm hover:bg-gray-50 flex items-center gap-2"
              >
                <Edit3 className="w-4 h-4" />
                Editar vault
              </button>
              <hr style={{ borderColor: colors.border }} />
              <button 
                onClick={() => handleDeleteVault(vault)}
                className="w-full text-left px-4 py-2 text-sm text-red-600 hover:bg-red-50 flex items-center gap-2"
              >
                <Trash2 className="w-4 h-4" />
                Eliminar vault
              </button>
            </div>
          </div>
        )}
      </div>
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
          className="fixed inset-0 bg-black/40 z-40 lg:hidden transition-opacity duration-300"
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
          className="px-6 py-3.5 border-b relative"
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

          {/* Vaults Section */}
          <div className="sidebar-nav-group" role="group" aria-label="Vaults">
            <div className="flex items-center justify-between mb-3">
              <h3 className="sidebar-group-title">
                Vaults
              </h3>
              <button
                onClick={() => setShowCreateVault(true)}
                className="p-1.5 rounded-md transition-colors duration-200"
                style={{
                  color: colors.textMuted,
                  backgroundColor: 'transparent'
                }}
                onMouseEnter={(e) => {
                  e.currentTarget.style.backgroundColor = colors.surfaceHover;
                  e.currentTarget.style.color = colors.primary;
                }}
                onMouseLeave={(e) => {
                  e.currentTarget.style.backgroundColor = 'transparent';
                  e.currentTarget.style.color = colors.textMuted;
                }}
                title="Crear nuevo vault"
              >
                <Plus className="w-4 h-4" />
              </button>
            </div>
            
            <div className="space-y-1">
              {/* Loading state */}
              {loading ? (
                <div className="flex items-center justify-center py-4">
                  <div className="animate-spin rounded-full h-5 w-5 border-b-2" style={{ borderColor: colors.primary }}></div>
                </div>
              ) : (
                /* Vault list */
                vaults.map((vault) => (
                  <VaultItem key={vault.id} vault={vault} />
                ))
              )}
              
              {/* Mostrar mensaje si no hay vaults */}
              {!loading && vaults.length === 0 && (
                <div className="text-center py-4">
                  <p className="text-sm" style={{ color: colors.textMuted }}>
                    No tienes vaults creados
                  </p>
                  <button
                    onClick={() => setShowCreateVault(true)}
                    className="text-xs mt-2 px-2 py-1 rounded"
                    style={{ color: colors.primary }}
                  >
                    Crear tu primer vault
                  </button>
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

      {/* Modales */}
      <CreateVaultModal
        isOpen={showCreateVault}
        onClose={() => setShowCreateVault(false)}
        onSubmit={handleCreateVault}
      />

      <ManageVaultModal
        isOpen={showManageVault}
        onClose={() => {
          setShowManageVault(false);
          setVaultToManage(null);
        }}
        vault={vaultToManage}
        onEdit={(vault) => {
          console.log('Edit vault:', vault);
          setShowManageVault(false);
        }}
        onDelete={(vault) => {
          console.log('Delete vault:', vault);
          setShowManageVault(false);
        }}
        onChangePrivacy={(vault) => {
          console.log('Change privacy:', vault);
          setShowManageVault(false);
        }}
        onChangePassword={(vault) => {
          console.log('Change password:', vault);
          setShowManageVault(false);
        }}
      />
    </>
  );
};