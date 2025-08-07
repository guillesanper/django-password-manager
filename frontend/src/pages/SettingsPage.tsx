import React, { useState } from 'react';
import { Save, Palette, Lock, Bell, Shield } from 'lucide-react';

interface SettingsState {
  theme: 'light' | 'dark' | 'pink';
  requirePasswordModify: boolean;
  requirePasswordDelete: boolean;
  notifications: 'enabled' | 'disabled';
}

export const SettingsPage: React.FC = () => {
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
    <div className="p-6 max-w-4xl mx-auto">
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-gray-900 mb-2">Ajustes</h1>
        <p className="text-gray-600">Personaliza tu experiencia y configura la seguridad</p>
      </div>

      {/* Mensaje de guardado */}
      {saved && (
        <div className="mb-6 bg-green-50 border border-green-200 text-green-800 px-4 py-3 rounded-lg flex items-center">
          <Save className="w-5 h-5 mr-2" />
          ¡Configuración guardada exitosamente!
        </div>
      )}

      <form onSubmit={handleSubmit}>
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Apariencia */}
          <div className="bg-white rounded-lg shadow-md">
            <div className="bg-gradient-to-r from-purple-50 to-pink-50 px-6 py-4 border-b border-gray-200 rounded-t-lg">
              <div className="flex items-center">
                <Palette className="w-5 h-5 text-purple-600 mr-2" />
                <h2 className="text-lg font-semibold text-purple-900">Apariencia</h2>
              </div>
            </div>

            <div className="p-6 space-y-6">
              <div>
                <label htmlFor="theme" className="block text-sm font-medium text-gray-700 mb-3">
                  Tema de la Interfaz
                </label>
                <div className="grid grid-cols-3 gap-3">
                  {[
                    { value: 'light' as const, label: 'Claro', preview: 'bg-white border-2' },
                    { value: 'dark' as const, label: 'Oscuro', preview: 'bg-gray-800 border-2' },
                    { value: 'pink' as const, label: 'Rosita', preview: 'bg-pink-100 border-2' }
                  ].map((theme) => (
                    <button
                      key={theme.value}
                      type="button"
                      onClick={() => handleInputChange('theme', theme.value)}
                      className={`p-3 rounded-lg text-center transition-all ${
                        settings.theme === theme.value
                          ? 'ring-2 ring-blue-500 border-blue-500'
                          : 'border-gray-300 hover:border-gray-400'
                      } border-2`}
                    >
                      <div className={`w-full h-8 rounded mb-2 ${theme.preview}`}></div>
                      <span className="text-sm font-medium">{theme.label}</span>
                    </button>
                  ))}
                </div>
              </div>
            </div>
          </div>

          {/* Seguridad */}
          <div className="bg-white rounded-lg shadow-md">
            <div className="bg-gradient-to-r from-red-50 to-orange-50 px-6 py-4 border-b border-gray-200 rounded-t-lg">
              <div className="flex items-center">
                <Shield className="w-5 h-5 text-red-600 mr-2" />
                <h2 className="text-lg font-semibold text-red-900">Seguridad</h2>
              </div>
            </div>

            <div className="p-6 space-y-6">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-4">
                  Solicitar contraseña para:
                </label>
                <div className="space-y-4">
                  <label className="flex items-start">
                    <input
                      type="checkbox"
                      checked={settings.requirePasswordModify}
                      onChange={(e) => handleInputChange('requirePasswordModify', e.target.checked)}
                      className="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded mt-0.5"
                    />
                    <div className="ml-3">
                      <span className="text-sm font-medium text-gray-700">Modificar contraseñas</span>
                      <p className="text-xs text-gray-500">Se requerirá autenticación para editar contraseñas existentes</p>
                    </div>
                  </label>
                  
                  <label className="flex items-start">
                    <input
                      type="checkbox"
                      checked={settings.requirePasswordDelete}
                      onChange={(e) => handleInputChange('requirePasswordDelete', e.target.checked)}
                      className="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded mt-0.5"
                    />
                    <div className="ml-3">
                      <span className="text-sm font-medium text-gray-700">Eliminar contraseñas</span>
                      <p className="text-xs text-gray-500">Se requerirá autenticación para eliminar contraseñas</p>
                    </div>
                  </label>
                </div>
              </div>
            </div>
          </div>

          {/* Notificaciones */}
          <div className="bg-white rounded-lg shadow-md">
            <div className="bg-gradient-to-r from-blue-50 to-indigo-50 px-6 py-4 border-b border-gray-200 rounded-t-lg">
              <div className="flex items-center">
                <Bell className="w-5 h-5 text-blue-600 mr-2" />
                <h2 className="text-lg font-semibold text-blue-900">Notificaciones</h2>
              </div>
            </div>

            <div className="p-6">
              <div>
                <label htmlFor="notifications" className="block text-sm font-medium text-gray-700 mb-3">
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
                      />
                      <div className="ml-3">
                        <span className="text-sm font-medium text-gray-700">{option.label}</span>
                        <p className="text-xs text-gray-500">{option.description}</p>
                      </div>
                    </label>
                  ))}
                </div>
              </div>
            </div>
          </div>

          {/* Configuración Avanzada */}
          <div className="bg-white rounded-lg shadow-md">
            <div className="bg-gradient-to-r from-gray-50 to-slate-50 px-6 py-4 border-b border-gray-200 rounded-t-lg">
              <div className="flex items-center">
                <Lock className="w-5 h-5 text-gray-600 mr-2" />
                <h2 className="text-lg font-semibold text-gray-900">Configuración Avanzada</h2>
              </div>
            </div>

            <div className="p-6 space-y-4">
              <div className="flex items-center justify-between p-4 bg-gray-50 rounded-lg">
                <div>
                  <h3 className="text-sm font-medium text-gray-900">Tiempo de sesión</h3>
                  <p className="text-xs text-gray-500">Cerrar sesión automáticamente después de inactividad</p>
                </div>
                <select className="text-sm border border-gray-300 rounded-md px-3 py-1 focus:outline-none focus:ring-2 focus:ring-blue-500">
                  <option>15 minutos</option>
                  <option>30 minutos</option>
                  <option>1 hora</option>
                  <option>Nunca</option>
                </select>
              </div>

              <div className="flex items-center justify-between p-4 bg-gray-50 rounded-lg">
                <div>
                  <h3 className="text-sm font-medium text-gray-900">Exportar datos</h3>
                  <p className="text-xs text-gray-500">Descargar una copia de tus datos</p>
                </div>
                <button 
                  type="button"
                  className="text-sm bg-gray-600 text-white px-4 py-2 rounded-md hover:bg-gray-700 transition-colors"
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
            className="flex items-center px-6 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2 transition-colors font-medium"
          >
            <Save className="w-5 h-5 mr-2" />
            Guardar cambios
          </button>
        </div>
      </form>
    </div>
  );
};