import React from 'react';
import { type ActiveSession } from '../../pages/SettingsPage';
import { LogOut } from 'lucide-react';
import { useUnifiedTheme } from '../../theme/UnifiedThemeProvider';

interface Props {
  sessions: ActiveSession[];
  onTerminateSession: (id: string) => void;
  onTerminateAllOther: () => void;
}

export const SessionManagement: React.FC<Props> = ({ sessions, onTerminateSession, onTerminateAllOther }) => {
  const { colors } = useUnifiedTheme();

  return (
    <div className="rounded-lg shadow-md mt-6" style={{ backgroundColor: colors.surface }}>
      <div className="px-6 py-4 border-b" style={{ borderColor: colors.border }}>
        <h3 className="text-lg font-semibold flex items-center" style={{ color: colors.textPrimary }}>
          <LogOut className="w-5 h-5 mr-2" />
          Sesiones Activas
        </h3>
      </div>
      <div className="p-6 space-y-4">
        {sessions.map(session => (
          <div key={session.id} className="flex items-center justify-between p-4 rounded-md border" style={{ borderColor: colors.border }}>
            <div>
              <p className="font-medium" style={{ color: colors.textPrimary }}>{session.device}</p>
              <p className="text-sm" style={{ color: colors.textSecondary }}>
                {session.location} • Última actividad: {session.lastActive}
              </p>
              {session.current && (
                <span className="text-xs px-2 py-1 rounded-full" style={{ backgroundColor: colors.primary, color: colors.primary }}>
                  Actual
                </span>
              )}
            </div>
            {!session.current && (
              <button
                type="button"
                onClick={() => onTerminateSession(session.id)}
                className="px-3 py-1 rounded-md text-sm"
                style={{ backgroundColor: colors.error, color: colors.primary }}
              >
                Cerrar
              </button>
            )}
          </div>
        ))}
        {sessions.length > 1 && (
          <button
            type="button"
            onClick={onTerminateAllOther}
            className="w-full px-3 py-2 rounded-md text-sm font-medium"
            style={{ backgroundColor: colors.error, color: colors.primary }}
          >
            Cerrar todas excepto esta
          </button>
        )}
      </div>
    </div>
  );
};
