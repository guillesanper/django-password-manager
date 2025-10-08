import React from 'react';
import { RefreshCw } from 'lucide-react';
import { useUnifiedTheme } from '../UnifiedThemeProvider';

interface SecurityHeaderProps {
  onRefresh: () => void;
  refreshing: boolean;
}

export const SecurityHeader: React.FC<SecurityHeaderProps> = ({ 
  onRefresh, 
  refreshing 
}) => {
  const { colors } = useUnifiedTheme();

  return (
    <div className="flex items-center justify-between">
      <div>
        <h1 className="text-3xl font-bold mb-2" style={{ color: colors.textPrimary }}>
          Vigilancia de Seguridad
        </h1>
        <p style={{ color: colors.textSecondary }}>
          Monitorea y mejora la seguridad de tus contraseñas
        </p>
      </div>
      <button
        onClick={onRefresh}
        disabled={refreshing}
        className="security-refresh-button"
      >
        <RefreshCw className={`security-refresh-button-icon ${refreshing ? 'animate-spin' : ''}`} />
        <span>Actualizar</span>
      </button>
    </div>
  );
};