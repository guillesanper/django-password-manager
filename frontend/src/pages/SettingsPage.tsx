import React, { useState } from 'react';
import { Save, Palette, Lock, Bell, Shield } from 'lucide-react';
import { useTheme, ThemeSelector } from '../theme'; // Importar el sistema de temas

interface SettingsState {
  theme: 'light' | 'dark' | 'pink';
  requirePasswordModify: boolean;
  requirePasswordDelete: boolean;
  notifications: 'enabled' | 'disabled';
}

export const SettingsPage: React.FC = () => {
  const { colors } = useTheme(); // Usar el hook del tema
  
  const [settings, setSettings] = useState<SettingsState>({
    theme: 'light',
    requirePasswordModify: true,
    requirePasswordDelete: true,
    notifications: 'enabled'
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

  return (
    <div 
      className="p-6 max-w-4xl mx-auto" 
      style={{ backgroundColor: colors.background, minHeight: '100vh' }}
    >
      <div className="mb-8">
        <h1 className="text-3xl font-bold mb-2" style={{ color: colors.textPrimary }}>Ajustes</h1>
        <p style={{ color: colors.textSecondary }}>Personaliza tu experiencia y configura la seguridad</p>
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
          <Save className="w-5 h-5 mr-2" />
          ¡Configuración guardada exitosamente!
        </div>
      )}

      <form onSubmit={handleSubmit}>
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Apariencia */}
          <div className="rounded-lg shadow-md" style={{ backgroundColor: colors.surface }}>
            <div 
              className="px-6 py-4 border-b rounded-t-lg"
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

            <div className="p-6 space-y-6">
              <div>
                <label htmlFor="theme" className="block text-sm font-medium mb-3" style={{ color: colors.textPrimary }}>
                  Tema de la Interfaz
                </label>
                
                {/* Usar el componente ThemeSelector del sistema de temas */}
                <ThemeSelector />
              </div>
            </div>
          </div>

          {/* Seguridad */}
          <div className="rounded-lg shadow-md" style={{ backgroundColor: colors.surface }}>
            <div 
              className="px-6 py-4 border-b rounded-t-lg"
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

            <div className="p-6 space-y-6">
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
                      <span className="text-sm font-medium" style={{ color: colors.textPrimary }}>Modificar contraseñas</span>
                      <p className="text-xs" style={{ color: colors.textMuted }}>Se requerirá autenticación para editar contraseñas existentes</p>
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
                      <span className="text-sm font-medium" style={{ color: colors.textPrimary }}>Eliminar contraseñas</span>
                      <p className="text-xs" style={{ color: colors.textMuted }}>Se requerirá autenticación para eliminar contraseñas</p>
                    </div>
                  </label>
                </div>
              </div>
            </div>
          </div>

          {/* Notificaciones */}
          <div className="rounded-lg shadow-md" style={{ backgroundColor: colors.surface }}>
            <div 
              className="px-6 py-4 border-b rounded-t-lg"
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

            <div className="p-6">
              <div>
                <label htmlFor="notifications" className="block text-sm font-medium mb-3" style={{ color: colors.textPrimary }}>
                  Estado de Notificaciones
                </label>
                <div className="space-y-3">
                  {[
                    { value: 'enabled' as const, label: 'Activadas', description: 'Recibir todas las notificaciones de seguridad' },
                    { value: 'disabled' as const, label: 'Desactivadas', description: 'No recibir notificaciones (no recomendado)' }
                  ].map((option) => (
                    <label key={option.value} className="flex items-start">
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
                      <div className="ml-3">
                        <span className="text-sm font-medium" style={{ color: colors.textPrimary }}>{option.label}</span>
                        <p className="text-xs" style={{ color: colors.textMuted }}>{option.description}</p>
                      </div>
                    </label>
                  ))}
                </div>
              </div>
            </div>
          </div>

          {/* Configuración Avanzada */}
          <div className="rounded-lg shadow-md" style={{ backgroundColor: colors.surface }}>
            <div 
              className="px-6 py-4 border-b rounded-t-lg"
              style={{ 
                backgroundColor: colors.backgroundSecondary,
                borderColor: colors.border
              }}
            >
              <div className="flex items-center">
                <Lock className="w-5 h-5 mr-2" style={{ color: colors.textSecondary }} />
                <h2 className="text-lg font-semibold" style={{ color: colors.textPrimary }}>Configuración Avanzada</h2>
              </div>
            </div>

            <div className="p-6 space-y-4">
              <div 
                className="flex items-center justify-between p-4 rounded-lg"
                style={{ backgroundColor: colors.backgroundSecondary }}
              >
                <div>
                  <h3 className="text-sm font-medium" style={{ color: colors.textPrimary }}>Tiempo de sesión</h3>
                  <p className="text-xs" style={{ color: colors.textMuted }}>Cerrar sesión automáticamente después de inactividad</p>
                </div>
                <select 
                  className="text-sm border rounded-md px-3 py-1 focus:outline-none focus:ring-2"
                  style={{
                    backgroundColor: colors.surface,
                    borderColor: colors.border,
                    color: colors.textPrimary
                  }}
                >
                  <option>15 minutos</option>
                  <option>30 minutos</option>
                  <option>1 hora</option>
                  <option>Nunca</option>
                </select>
              </div>

              <div 
                className="flex items-center justify-between p-4 rounded-lg"
                style={{ backgroundColor: colors.backgroundSecondary }}
              >
                <div>
                  <h3 className="text-sm font-medium" style={{ color: colors.textPrimary }}>Exportar datos</h3>
                  <p className="text-xs" style={{ color: colors.textMuted }}>Descargar una copia de tus datos</p>
                </div>
                <button 
                  type="button"
                  className="text-sm px-4 py-2 rounded-md transition-colors"
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
            </div>
          </div>
        </div>

        {/* Botón Guardar */}
        <div className="mt-8 flex justify-end">
          <button
            type="submit"
            className="flex items-center px-6 py-3 rounded-lg focus:outline-none focus:ring-2 focus:ring-offset-2 transition-colors font-medium"
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