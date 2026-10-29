import React, { useState } from 'react';
import { useUnifiedTheme } from '../components/UnifiedThemeProvider';
import { TopbarNavigation } from '../components/settings/TopbarNavigation';
import { SaveMessage } from '../components/settings/SaveMessage';
import { UserSettings } from '../components/settings/sections/UserSettings';
import { SecuritySettings } from '../components/settings/sections/SecuritySettings';
import { ThemeSettings } from '../components/settings/sections/ThemeSettings';
import { NotificationSettings } from '../components/settings/sections/NotificationSettings';
import { PrivacySettings } from '../components/settings/sections/PrivacySettings';
import { AdvancedSettings } from '../components/settings/sections/AdvancedSettings';

export interface SettingsState {
  nombre: string;
  correo: string;
  idioma: string;
  zonaHoraria: string;
  contrasena: string;
  notificacionesEmail: boolean;
  notificacionesSMS: boolean;
  perfilPublico: boolean;
  compartirDatos: boolean;
  logsActividades: boolean;
}

export interface ActiveSession {
  id: string;
  device: string;
  location: string;
  current: boolean;
  lastActive: string;
}

const mockSessions: ActiveSession[] = [
  { id: '1', device: 'Chrome en Windows', location: 'Madrid, España', current: true, lastActive: 'Ahora mismo' },
  { id: '2', device: 'Safari en iPhone', location: 'Barcelona, España', current: false, lastActive: 'Hace 2 horas' },
  { id: '3', device: 'Firefox en Linux', location: 'Valencia, España', current: false, lastActive: 'Ayer' },
];

export const SettingsPage: React.FC = () => {
  const { colors } = useUnifiedTheme();
  const [activeTab, setActiveTab] = useState<string>('usuario');
  const [sessions, setSessions] = useState<ActiveSession[]>(mockSessions);
  const [settings, setSettings] = useState<SettingsState>({
    nombre: '',
    correo: '',
    idioma: 'es',
    zonaHoraria: 'Europe/Madrid',
    contrasena: '',
    notificacionesEmail: true,
    notificacionesSMS: false,
    perfilPublico: true,
    compartirDatos: false,
    logsActividades: true,
  });
  const [saved, setSaved] = useState(false);

  const handleInputChange = (name: keyof SettingsState, value: string | boolean) => {
    setSettings(prev => ({ ...prev, [name]: value }));
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    console.log("Configuración guardada:", settings);
    setSaved(true);
    setTimeout(() => setSaved(false), 3000);
  };

  const handleTerminateSession = (id: string) => {
    setSessions(prev => prev.filter(s => s.id !== id));
  };

  const handleTerminateAllOther = () => {
    setSessions(prev => prev.filter(s => s.current));
  };

  return (
    <div className="min-h-screen" style={{ backgroundColor: colors.background }}>
      {saved && <SaveMessage />}

      <TopbarNavigation activeTab={activeTab} setActiveTab={setActiveTab} />

        <form onSubmit={handleSubmit} className=" lg:mt-0 lg:col-span-9">
          {activeTab === 'usuario' && (
            <UserSettings settings={settings} onChange={handleInputChange} />
          )}
          {activeTab === 'seguridad' && (
            <SecuritySettings
              settings={settings}
              onChange={handleInputChange}
              sessions={sessions}
              onTerminateSession={handleTerminateSession}
              onTerminateAllOther={handleTerminateAllOther}
            />
          )}
          {activeTab === 'temas' && <ThemeSettings />}
          {activeTab === 'notificaciones' && (
            <NotificationSettings settings={settings} onChange={handleInputChange} />
          )}
          {activeTab === 'privacidad' && (
            <PrivacySettings settings={settings} onChange={handleInputChange} />
          )}
          {activeTab === 'avanzado' && (
            <AdvancedSettings settings={settings} onChange={handleInputChange} />
          )}
        </form>
    </div>
  );
};
