import React, { useState } from 'react';
import { Save, Palette, Lock, Bell, Shield, Monitor, Sun, Moon } from 'lucide-react';
import { useUnifiedTheme, type ThemeName, type ThemeMode } from '../theme/UnifiedThemeProvider';

interface SettingsState {
  requirePasswordModify: boolean;
  requirePasswordDelete: boolean;
  notifications: 'enabled' | 'disabled';
  sessionTimeout: '15' | '30' | '60' | 'never';
}

// Componente selector de tema unificado mejorado
const UnifiedThemeSelector: React.FC = () => {
  const { 
    themeMode, 
    themeName, 
    setThemeMode, 
    setThemeName, 
    availableThemes,
    colors,
    systemPrefersDark
  } = useUnifiedTheme();

  const themeLabels: Record<ThemeName, string> = {
    light: '☀️ Claro',
    dark: '🌙 Oscuro',
    pink: '🌸 Rosa',
    blue: '🌊 Azul',
    purple: '💜 Púrpura',
  };

  const modeLabels: Record<ThemeMode, { label: string; icon: React.ReactNode; description: string }> = {
    system: {
      label: 'Sistema',
      icon: <Monitor className="w-4 h-4" />,
      description: `Sigue la preferencia del sistema (actualmente ${systemPrefersDark ? 'oscuro' : 'claro'})`
    },
    light: {
      label: 'Claro',
      icon: <Sun className="w-4 h-4" />,
      description: 'Siempre usar tema claro'
    },
    dark: {
      label: 'Oscuro',
      icon: <Moon className="w-4 h-4" />,
      description: 'Siempre usar tema oscuro'
    }
  };

  return (
    <div className="space-y-6">
      {/* Selector de modo (system/light/dark) */}
      <div>
        <label className="block text-sm font-medium mb-3" style={{ color: colors.textPrimary }}>
          Modo de Tema
        </label>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
          {(Object.keys(modeLabels) as ThemeMode[]).map((mode) => {
            const modeInfo = modeLabels[mode];
            const isSelected = themeMode === mode;
            
            return (
              <button
                key={mode}
                onClick={() => setThemeMode(mode)}
                className={`
                  relative p-4 rounded-lg border-2 transition-all duration-200 text-left
                  ${isSelected 
                    ? 'border-opacity-100 shadow-md' 
                    : 'border-opacity-50 hover:border-opacity-75'
                  }
                `}
                style={{
                  backgroundColor: isSelected ? colors.primaryHover + '10' : colors.surface,
                  borderColor: isSelected ? colors.primary : colors.border,
                }}
              >
                <div className="flex items-center space-x-3">
                  <div 
                    className="p-2 rounded-full"
                    style={{ 
                      backgroundColor: isSelected ? colors.primary : colors.backgroundSecondary,
                      color: isSelected ? colors.primaryText : colors.textMuted
                    }}
                  >
                    {modeInfo.icon}
                  </div>
                  <div>
                    <div 
                      className="font-medium text-sm"
                      style={{ color: colors.textPrimary }}
                    >
                      {modeInfo.label}
                    </div>
                    <div 
                      className="text-xs mt-1"
                      style={{ color: colors.textMuted }}
                    >
                      {modeInfo.description}
                    </div>
                  </div>
                </div>
              </button>
            );
          })}
        </div>
      </div>

      {/* Selector de esquema de color (solo si no está en modo dark system) */}
      {!(themeMode === 'dark') && (
        <div>
          <label className="block text-sm font-medium mb-3" style={{ color: colors.textPrimary }}>
            Esquema de Colores
          </label>
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3">
            {availableThemes.filter(theme => theme !== 'dark').map((theme) => {
              const isSelected = themeName === theme;
              
              return (
                <button
                  key={theme}
                  onClick={() => setThemeName(theme)}
                  className={`
                    relative p-4 rounded-lg border-2 transition-all duration-200 group
                    ${isSelected 
                      ? 'border-opacity-100 shadow-md scale-105' 
                      : 'border-opacity-30 hover:border-opacity-60 hover:scale-102'
                    }
                  `}
                  style={{
                    backgroundColor: colors.surface,
                    borderColor: isSelected ? colors.primary : colors.border,
                  }}
                >
                  {/* Vista previa del color */}
                  <div className="flex flex-col items-center space-y-2">
                    <div 
                      className="w-8 h-8 rounded-full border-2 border-white shadow-sm"
                      style={{ 
                        backgroundColor: theme === 'light' ? '#6366f1' : 
                                       theme === 'pink' ? '#ec4899' :
                                       theme === 'blue' ? '#3b82f6' :
                                       theme === 'purple' ? '#8b5cf6' : '#6366f1'
                      }}
                    />
                    <div 
                      className="text-xs font-medium text-center"
                      style={{ color: colors.textPrimary }}
                    >
                      {themeLabels[theme]}
                    </div>
                  </div>
                  
                  {isSelected && (
                    <div 
                      className="absolute top-1 right-1 w-3 h-3 rounded-full"
                      style={{ backgroundColor: colors.success }}
                    />
                  )}
                </button>
              );
            })}
          </div>
        </div>
      )}

      {/* Información del tema actual */}
      <div 
        className="p-4 rounded-lg border"
        style={{ 
          backgroundColor: colors.backgroundSecondary,
          borderColor: colors.border
        }}
      >
        <div className="flex items-center space-x-2 mb-2">
          <Palette className="w-4 h-4" style={{ color: colors.primary }} />
          <span className="text-sm font-medium" style={{ color: colors.textPrimary }}>
            Tema Actual
          </span>
        </div>
        <div className="text-sm" style={{ color: colors.textSecondary }}>
          Modo: {modeLabels[themeMode].label} • 
          Color: {themeLabels[themeName]} • 
          Estado: {systemPrefersDark && themeMode === 'system' ? 'Modo oscuro del sistema' : 'Personalizado'}
        </div>
      </div>
    </div>
  );
};

export const SettingsPage: React.FC = () => {
  const { colors } = useUnifiedTheme();
  
  const [settings, setSettings] = useState<SettingsState>({
    requirePasswordModify: true,
    requirePasswordDelete: true,
    notifications: 'enabled',
    sessionTimeout: '30'
  });

  const [saved, setSaved] = useState<boolean>(false);

  const handleInputChange = (name: keyof SettingsState, value: string | boolean): void => {
    setSettings(prev => ({
      ...prev,
      [name]: value
    }));
  };

  const handleSubmit = (e: React.FormEvent<HTMLFormElement>): void => {
    e.preventDefault();
    console.log('Configuración guardada:', settings);
    setSaved(true);
    setTimeout(() => setSaved(false), 3000);
    // Aquí irían las llamadas a la API
  };

  const handleExportData = () => {
    // Simular exportación de datos
    const data = {
      settings,
      exportDate: new Date().toISOString(),
      version: '1.0.0'
    };
    
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'password-manager-settings.json';
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div 
      className="p-4 sm:p-6 max-w-6xl mx-auto" 
      style={{ backgroundColor: colors.background, minHeight: '100vh' }}
    >
      {/* Header responsive */}
      <div className="mb-6 sm:mb-8">
        <h1 className="text-2xl sm:text-3xl font-bold mb-2" style={{ color: colors.textPrimary }}>
          Ajustes
        </h1>
        <p className="text-sm sm:text-base" style={{ color: colors.textSecondary }}>
          Personaliza tu experiencia y configura la seguridad
        </p>
      </div>

      {/* Mensaje de guardado */}
      {saved && (
        <div 
          className="mb-6 border px-4 py-3 rounded-lg flex items-center"
          style={{ 
            backgroundColor: colors.success + '10',
            borderColor: colors.success + '30',
            color: colors.success
          }}
        >
          <Save className="w-5 h-5 mr-2 flex-shrink-0" />
          <span className="text-sm sm:text-base">¡Configuración guardada exitosamente!</span>
        </div>
      )}

      <form onSubmit={handleSubmit}>
        <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
          {/* Apariencia */}
          <div className="xl:col-span-2">
            <div className="rounded-lg shadow-md" style={{ backgroundColor: colors.surface }}>
              <div 
                className="px-4 sm:px-6 py-4 border-b rounded-t-lg"
                style={{ 
                  background: `linear-gradient(to right, ${colors.primary}15, ${colors.secondary}15)`,
                  borderColor: colors.border
                }}
              >
                <div className="flex items-center">
                  <Palette className="w-5 h-5 mr-2" style={{ color: colors.primary }} />
                  <h2 className="text-lg font-semibold" style={{ color: colors.textPrimary }}>Apariencia</h2>
                </div>
              </div>

              <div className="p-4 sm:p-6">
                <UnifiedThemeSelector />
              </div>
            </div>
          </div>

          {/* Seguridad */}
          <div className="rounded-lg shadow-md" style={{ backgroundColor: colors.surface }}>
            <div 
              className="px-4 sm:px-6 py-4 border-b rounded-t-lg"
              style={{ 
                background: `linear-gradient(to right, ${colors.error}15, ${colors.warning}15)`,
                borderColor: colors.border
              }}
            >
              <div className="flex items-center">
                <Shield className="w-5 h-5 mr-2" style={{ color: colors.error }} />
                <h2 className="text-lg font-semibold" style={{ color: colors.textPrimary }}>Seguridad</h2>
              </div>
            </div>

            <div className="p-4 sm:p-6 space-y-6">
              <div>
                <label className="block text-sm font-medium mb-4" style={{ color: colors.textPrimary }}>
                  Solicitar contraseña para:
                </label>
                <div className="space-y-4">
                  <label className="flex items-start">
                    <input
                      type="checkbox"
                      checked={settings.requirePasswordModify}
                      onChange={(e) => handleInputChange('requirePasswordModify', e.target.checked)}
                      className="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded mt-0.5"
                      style={{
                        accentColor: colors.primary
                      }}
                    />
                    <div className="ml-3">
                      <span className="text-sm font-medium" style={{ color: colors.textPrimary }}>
                        Modificar contraseñas
                      </span>
                      <p className="text-xs mt-1" style={{ color: colors.textMuted }}>
                        Se requerirá autenticación para editar contraseñas existentes
                      </p>
                    </div>
                  </label>
                  
                  <label className="flex items-start">
                    <input
                      type="checkbox"
                      checked={settings.requirePasswordDelete}
                      onChange={(e) => handleInputChange('requirePasswordDelete', e.target.checked)}
                      className="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded mt-0.5"
                      style={{
                        accentColor: colors.primary
                      }}
                    />
                    <div className="ml-3">
                      <span className="text-sm font-medium" style={{ color: colors.textPrimary }}>
                        Eliminar contraseñas
                      </span>
                      <p className="text-xs mt-1" style={{ color: colors.textMuted }}>
                        Se requerirá autenticación para eliminar contraseñas
                      </p>
                    </div>
                  </label>
                </div>
              </div>

              {/* Tiempo de sesión */}
              <div>
                <label className="block text-sm font-medium mb-3" style={{ color: colors.textPrimary }}>
                  Tiempo de sesión
                </label>
                <select 
                  value={settings.sessionTimeout}
                  onChange={(e) => handleInputChange('sessionTimeout', e.target.value as '15' | '30' | '60' | 'never')}
                  className="w-full text-sm border rounded-md px-3 py-2 focus:outline-none focus:ring-2"
                  style={{
                    backgroundColor: colors.surface,
                    borderColor: colors.border,
                    color: colors.textPrimary
                  }}
                  onFocus={(e) => {
                    e.currentTarget.style.borderColor = colors.primary;
                    e.currentTarget.style.boxShadow = `0 0 0 1px ${colors.primary}`;
                  }}
                  onBlur={(e) => {
                    e.currentTarget.style.borderColor = colors.border;
                    e.currentTarget.style.boxShadow = 'none';
                  }}
                >
                  <option value="15">15 minutos</option>
                  <option value="30">30 minutos</option>
                  <option value="60">1 hora</option>
                  <option value="never">Nunca</option>
                </select>
                <p className="text-xs mt-1" style={{ color: colors.textMuted }}>
                  Cerrar sesión automáticamente después de inactividad
                </p>
              </div>
            </div>
          </div>

          {/* Notificaciones */}
          <div className="rounded-lg shadow-md" style={{ backgroundColor: colors.surface }}>
            <div 
              className="px-4 sm:px-6 py-4 border-b rounded-t-lg"
              style={{ 
                background: `linear-gradient(to right, ${colors.info}15, ${colors.primary}15)`,
                borderColor: colors.border
              }}
            >
              <div className="flex items-center">
                <Bell className="w-5 h-5 mr-2" style={{ color: colors.info }} />
                <h2 className="text-lg font-semibold" style={{ color: colors.textPrimary }}>Notificaciones</h2>
              </div>
            </div>

            <div className="p-4 sm:p-6">
              <div>
                <label className="block text-sm font-medium mb-3" style={{ color: colors.textPrimary }}>
                  Estado de Notificaciones
                </label>
                <div className="space-y-3">
                  {[
                    { 
                      value: 'enabled' as const, 
                      label: 'Activadas', 
                      description: 'Recibir todas las notificaciones de seguridad',
                      icon: <Bell className="w-4 h-4" />
                    },
                    { 
                      value: 'disabled' as const, 
                      label: 'Desactivadas', 
                      description: 'No recibir notificaciones (no recomendado)',
                      icon: <Bell className="w-4 h-4 opacity-50" />
                    }
                  ].map((option) => (
                    <label key={option.value} className="flex items-start cursor-pointer group">
                      <input
                        type="radio"
                        name="notifications"
                        value={option.value}
                        checked={settings.notifications === option.value}
                        onChange={(e) => handleInputChange('notifications', e.target.value as 'enabled' | 'disabled')}
                        className="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 mt-0.5"
                        style={{
                          accentColor: colors.primary
                        }}
                      />
                      <div className="ml-3 flex items-start space-x-2">
                        <div style={{ color: colors.textMuted }} className="mt-0.5">
                          {option.icon}
                        </div>
                        <div>
                          <span className="text-sm font-medium" style={{ color: colors.textPrimary }}>
                            {option.label}
                          </span>
                          <p className="text-xs mt-1" style={{ color: colors.textMuted }}>
                            {option.description}
                          </p>
                        </div>
                      </div>
                    </label>
                  ))}
                </div>
              </div>
            </div>
          </div>

          {/* Configuración Avanzada */}
          <div className="xl:col-span-2">
            <div className="rounded-lg shadow-md" style={{ backgroundColor: colors.surface }}>
              <div 
                className="px-4 sm:px-6 py-4 border-b rounded-t-lg"
                style={{ 
                  backgroundColor: colors.backgroundSecondary,
                  borderColor: colors.border
                }}
              >
                <div className="flex items-center">
                  <Lock className="w-5 h-5 mr-2" style={{ color: colors.textSecondary }} />
                  <h2 className="text-lg font-semibold" style={{ color: colors.textPrimary }}>
                    Configuración Avanzada
                  </h2>
                </div>
              </div>

              <div className="p-4 sm:p-6">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div 
                    className="flex flex-col sm:flex-row sm:items-center justify-between p-4 rounded-lg space-y-2 sm:space-y-0"
                    style={{ backgroundColor: colors.backgroundSecondary }}
                  >
                    <div className="flex-1">
                      <h3 className="text-sm font-medium" style={{ color: colors.textPrimary }}>
                        Exportar datos
                      </h3>
                      <p className="text-xs mt-1" style={{ color: colors.textMuted }}>
                        Descargar una copia de tu configuración
                      </p>
                    </div>
                    <button 
                      type="button"
                      onClick={handleExportData}
                      className="text-sm px-4 py-2 rounded-md transition-colors whitespace-nowrap"
                      style={{
                        backgroundColor: colors.secondary,
                        color: colors.textPrimary
                      }}
                      onMouseEnter={(e) => {
                        e.currentTarget.style.backgroundColor = colors.secondaryHover;
                      }}
                      onMouseLeave={(e) => {
                        e.currentTarget.style.backgroundColor = colors.secondary;
                      }}
                    >
                      Exportar
                    </button>
                  </div>

                  <div 
                    className="flex flex-col sm:flex-row sm:items-center justify-between p-4 rounded-lg space-y-2 sm:space-y-0"
                    style={{ backgroundColor: colors.backgroundSecondary }}
                  >
                    <div className="flex-1">
                      <h3 className="text-sm font-medium" style={{ color: colors.textPrimary }}>
                        Limpiar caché
                      </h3>
                      <p className="text-xs mt-1" style={{ color: colors.textMuted }}>
                        Eliminar datos temporales almacenados
                      </p>
                    </div>
                    <button 
                      type="button"
                      className="text-sm px-4 py-2 rounded-md transition-colors whitespace-nowrap"
                      style={{
                        backgroundColor: colors.warning + '20',
                        color: colors.warning,
                        border: `1px solid ${colors.warning}40`
                      }}
                      onMouseEnter={(e) => {
                        e.currentTarget.style.backgroundColor = colors.warning + '30';
                      }}
                      onMouseLeave={(e) => {
                        e.currentTarget.style.backgroundColor = colors.warning + '20';
                      }}
                    >
                      Limpiar
                    </button>
                  </div>
                </div>

                {/* Información adicional */}
                <div 
                  className="mt-6 p-4 rounded-lg border-l-4"
                  style={{ 
                    backgroundColor: colors.info + '10',
                    borderLeftColor: colors.info
                  }}
                >
                  <div className="flex items-start">
                    <Shield className="w-5 h-5 mr-2 mt-0.5" style={{ color: colors.info }} />
                    <div>
                      <h3 className="text-sm font-medium" style={{ color: colors.textPrimary }}>
                        Información de Seguridad
                      </h3>
                      <p className="text-xs mt-1" style={{ color: colors.textSecondary }}>
                        Todos los cambios en la configuración de seguridad se aplican inmediatamente. 
                        Se recomienda mantener activadas las opciones de autenticación adicional.
                      </p>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Botón Guardar responsive */}
        <div className="mt-6 sm:mt-8 flex flex-col sm:flex-row justify-end space-y-3 sm:space-y-0 sm:space-x-3">
          <button
            type="button"
            className="w-full sm:w-auto flex items-center justify-center px-6 py-3 rounded-lg focus:outline-none focus:ring-2 focus:ring-offset-2 transition-colors font-medium order-2 sm:order-1"
            style={{
              backgroundColor: colors.secondary,
              color: colors.textPrimary
            }}
            onMouseEnter={(e) => {
              e.currentTarget.style.backgroundColor = colors.secondaryHover;
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.backgroundColor = colors.secondary;
            }}
          >
            Cancelar
          </button>
          
          <button
            type="submit"
            className="w-full sm:w-auto flex items-center justify-center px-6 py-3 rounded-lg focus:outline-none focus:ring-2 focus:ring-offset-2 transition-colors font-medium order-1 sm:order-2"
            style={{
              backgroundColor: colors.primary,
              color: colors.primaryText
            }}
            onMouseEnter={(e) => {
              e.currentTarget.style.backgroundColor = colors.primaryHover;
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.backgroundColor = colors.primary;
            }}
          >
            <Save className="w-5 h-5 mr-2" />
            Guardar cambios
          </button>
        </div>
      </form>
    </div>
  );
};