import React from 'react';
import { User, Shield, Palette, Bell, Lock, Settings } from 'lucide-react';
import { useUnifiedTheme } from '../../theme/UnifiedThemeProvider';

interface Props {
  activeTab: string;
  setActiveTab: (tab: string) => void;
}

export const SidebarNavigation: React.FC<Props> = ({ activeTab, setActiveTab }) => {
  const { colors } = useUnifiedTheme();

  const tabs = [
    { id: 'usuario', name: 'Usuario', icon: <User className="w-5 h-5" />, color: 'indigo' },
    { id: 'seguridad', name: 'Seguridad', icon: <Shield className="w-5 h-5" />, color: 'emerald' },
    { id: 'temas', name: 'Temas', icon: <Palette className="w-5 h-5" />, color: 'purple' },
    { id: 'notificaciones', name: 'Notificaciones', icon: <Bell className="w-5 h-5" />, color: 'amber' },
    { id: 'privacidad', name: 'Privacidad', icon: <Lock className="w-5 h-5" />, color: 'rose' },
    { id: 'avanzado', name: 'Avanzado', icon: <Settings className="w-5 h-5" />, color: 'gray' },
  ];

  const getButtonStyles = (tab: any, isActive: boolean) => {
    const baseStyles = `
      w-full flex items-center px-6 py-4 text-left font-medium text-sm 
      transition-all duration-300 ease-out relative overflow-hidden
      border-none cursor-pointer rounded-xl mb-2 group
      hover:transform hover:translate-x-1 hover:scale-[1.02]
    `;

    if (isActive) {
      return `${baseStyles} 
        bg-gradient-to-r shadow-lg transform translate-x-2 scale-[1.02]
        font-semibold text-white
        ${getActiveGradient(tab.color)}
      `;
    }

    return `${baseStyles} 
      bg-transparent text-gray-600 dark:text-gray-300
      hover:bg-gradient-to-r hover:text-white hover:shadow-md
      ${getHoverGradient(tab.color)}
    `;
  };

  const getActiveGradient = (color: string) => {
    const gradients : Record<string,string> = {
      indigo: 'from-indigo-500 to-indigo-600',
      emerald: 'from-emerald-500 to-emerald-600',
      purple: 'from-purple-500 to-purple-600',
      amber: 'from-amber-500 to-amber-600',
      rose: 'from-rose-500 to-rose-600',
      gray: 'from-gray-500 to-gray-600',
    };
    return gradients[color] || gradients.indigo;
  };

  const getHoverGradient = (color: string) => {
    const gradients : Record<string,string> = {
      indigo: 'hover:from-indigo-400 hover:to-indigo-500',
      emerald: 'hover:from-emerald-400 hover:to-emerald-500',
      purple: 'hover:from-purple-400 hover:to-purple-500',
      amber: 'hover:from-amber-400 hover:to-amber-500',
      rose: 'hover:from-rose-400 hover:to-rose-500',
      gray: 'hover:from-gray-400 hover:to-gray-500',
    };
    return gradients[color] || gradients.indigo;
  };


  const getIconStyles = (tab: any, isActive: boolean) => {
    const baseStyles = `
      w-5 h-5 mr-4 transition-all duration-300 group-hover:scale-110 
      flex-shrink-0
    `;

    if (isActive) {
      return `${baseStyles} text-white drop-shadow-sm transform scale-110`;
    }

    return `${baseStyles} ${getIconColor(tab.color)} group-hover:text-white`;
  };

  const getIconColor = (color: string) => {
    const colors : Record<string,string>= {
      indigo: 'text-indigo-500',
      emerald: 'text-emerald-500',
      purple: 'text-purple-500',
      amber: 'text-amber-500',
      rose: 'text-rose-500',
      gray: 'text-gray-500',
    };
    return colors[color] || colors.indigo;
  };

  return (
    <aside className="lg:col-span-3">
      {/* Header del Sidebar */}
      <div 
        className="px-6 py-6 mb-6 border-b border-opacity-20"
        style={{ borderColor: colors.border }}
      >
        <h2 
          className="text-xl font-bold mb-2" 
          style={{ color: colors.textPrimary }}
        >
          Configuración
        </h2>
        <p 
          className="text-sm opacity-70" 
          style={{ color: colors.textSecondary }}
        >
          Personaliza tu experiencia
        </p>
      </div>

      {/* Navegación */}
      <nav className="px-4 space-y-1">
        {tabs.map(tab => (
          <div key={tab.id} className="relative">
            <button
              onClick={() => setActiveTab(tab.id)}
              className={getButtonStyles(tab, activeTab === tab.id)}
            >
              {/* Efecto de brillo sutil */}
              <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white to-transparent opacity-0 group-hover:opacity-10 group-hover:translate-x-full transition-all duration-700 transform -translate-x-full"></div>
              
              {/* Indicador lateral para elemento activo */}
              {activeTab === tab.id && (
                <div 
                  className={`absolute left-0 top-1/2 transform -translate-y-1/2 w-1 h-8 rounded-r-full ${getActiveGradient(tab.color).replace('from-', 'bg-').split(' ')[0]}`}
                  style={{ left: '-1rem' }}
                ></div>
              )}
              
              {/* Icono */}
              <div className={getIconStyles(tab, activeTab === tab.id)}>
                {tab.icon}
              </div>
              
              {/* Texto */}
              <span className="relative z-10 transition-all duration-300">
                {tab.name}
              </span>
            </button>
          </div>
        ))}
      </nav>

      {/* Footer del sidebar */}
      <div 
        className="mt-12 px-6 pt-6 border-t border-opacity-20"
        style={{ borderColor: colors.border }}
      >
        <div className="flex items-center space-x-3">
          <div 
            className="w-8 h-8 rounded-full bg-gradient-to-br from-indigo-400 to-purple-500 flex items-center justify-center"
          >
            <User className="w-4 h-4 text-white" />
          </div>
          <div>
            <p 
              className="text-sm font-medium" 
              style={{ color: colors.textPrimary }}
            >
              Usuario
            </p>
            <p 
              className="text-xs opacity-60" 
              style={{ color: colors.textSecondary }}
            >
              Configuración personal
            </p>
          </div>
        </div>
      </div>
    </aside>
  );
};