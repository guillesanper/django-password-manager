import React from 'react';
import { User, Shield, Palette, Bell, Lock, Settings } from 'lucide-react';
import { useUnifiedTheme } from '../UnifiedThemeProvider';

interface Props {
  activeTab: string;
  setActiveTab: (tab: string) => void;
}

export const TopbarNavigation: React.FC<Props> = ({ activeTab, setActiveTab }) => {
  const { colors } = useUnifiedTheme();

  const tabs = [
    { id: 'usuario', name: 'Usuario', icon: <User className="w-5 h-5" />, color: 'indigo' },
    { id: 'seguridad', name: 'Seguridad', icon: <Shield className="w-5 h-5" />, color: 'emerald' },
    { id: 'temas', name: 'Temas', icon: <Palette className="w-5 h-5" />, color: 'purple' },
    { id: 'notificaciones', name: 'Notificaciones', icon: <Bell className="w-5 h-5" />, color: 'amber' },
    { id: 'privacidad', name: 'Privacidad', icon: <Lock className="w-5 h-5" />, color: 'rose' },
    { id: 'avanzado', name: 'Avanzado', icon: <Settings className="w-5 h-5" />, color: 'gray' },
  ];

  const getTabClass = (tab: any, isActive: boolean) => {
    if (isActive) {
      return `settings-tab settings-tab-active settings-tab-${tab.color}`;
    }
    return `settings-tab settings-tab-inactive settings-tab-hover-${tab.color}`;
  };

  return (
    <div className="settings-topbar">
      

      {/* Navigation Tabs */}
      <nav className="settings-nav" style={{ borderColor: colors.border }}>
        <div className="settings-nav-container">
          <div className="settings-tabs-wrapper">
            {tabs.map(tab => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={getTabClass(tab, activeTab === tab.id)}
                style={{
                  color: activeTab === tab.id ? 'white' : colors.textSecondary,
                }}
              >
                <span className="settings-tab-icon">
                  {tab.icon}
                </span>
                <span className="settings-tab-text">
                  {tab.name}
                </span>
                {activeTab === tab.id && (
                  <div className={`settings-tab-indicator settings-indicator-${tab.color}`} />
                )}
              </button>
            ))}
          </div>
        </div>
      </nav>
    </div>
  );
};