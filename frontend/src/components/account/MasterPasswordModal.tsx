import React,{useState} from 'react';
import { useUnifiedTheme } from '../UnifiedThemeProvider';

// Crear también el MasterPasswordModal
interface MasterPasswordModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSubmit: (masterPassword: string) => void;
  loading?: boolean;
  error?: string;
  title?: string;
  description?: string;
}

export const MasterPasswordModal: React.FC<MasterPasswordModalProps> = ({
  isOpen,
  onClose,
  onSubmit,
  loading = false,
  error = '',
  title = "Confirmar Master Password",
  description = "Ingresa tu contraseña maestra para confirmar el cambio de contraseña"
}) => {
  const { colors } = useUnifiedTheme();
  const [masterPassword, setMasterPassword] = useState('');

  React.useEffect(() => {
    if (!isOpen) {
      setMasterPassword('');
    }
  }, [isOpen]);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (masterPassword.trim() && !loading) {
      onSubmit(masterPassword.trim());
    }
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 flex items-center justify-center p-4 z-50">
      <div 
        className="absolute inset-0"
        style={{
          backgroundColor: 'rgba(0, 0, 0, 0.4)',
          backdropFilter: 'blur(8px)',
        }}
        onClick={!loading ? onClose : undefined}
      />
      <div 
        className="relative max-w-md w-full rounded-2xl shadow-2xl border p-6"
        onClick={(e) => e.stopPropagation()}
        style={{ 
          backgroundColor: colors.surface,
          borderColor: colors.border,
        }}
      >
        <h3 className="text-lg font-semibold mb-2" style={{ color: colors.textPrimary }}>
          {title}
        </h3>
        <p className="text-sm mb-4" style={{ color: colors.textSecondary }}>
          {description}
        </p>

        <form onSubmit={handleSubmit} className="space-y-4">
          <input
            type="password"
            value={masterPassword}
            onChange={(e) => setMasterPassword(e.target.value)}
            placeholder="Contraseña maestra"
            className="w-full px-3 py-2 rounded-lg border focus:outline-none focus:ring-2"
            style={{
              backgroundColor: colors.background,
              borderColor: error ? colors.error : colors.border,
              color: colors.textPrimary
            }}
            disabled={loading}
            autoFocus
            required
          />

          {error && (
            <p className="text-sm" style={{ color: colors.error }}>
              {error}
            </p>
          )}

          <div className="flex gap-3">
            <button
              type="button"
              onClick={onClose}
              className="flex-1 px-4 py-2 rounded-lg border"
              style={{
                backgroundColor: colors.background,
                borderColor: colors.border,
                color: colors.textSecondary
              }}
              disabled={loading}
            >
              Cancelar
            </button>
            <button
              type="submit"
              className="flex-1 px-4 py-2 rounded-lg font-medium text-white"
              style={{ 
                backgroundColor: masterPassword.trim() ? colors.primary : colors.textMuted,
                opacity: masterPassword.trim() ? 1 : 0.5,
              }}
              disabled={loading || !masterPassword.trim()}
            >
              {loading ? 'Verificando...' : 'Confirmar'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};