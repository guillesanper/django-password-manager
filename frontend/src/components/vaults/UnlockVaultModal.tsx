// Modal para desbloquear vault

import React, { useState, useEffect } from 'react';
import { Lock, Eye, EyeOff } from 'lucide-react';
import { useUnifiedTheme } from '../../theme/UnifiedThemeProvider';
import { type Vault, VAULT_COLORS} from '../../services/vaultService';

interface UnlockVaultModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSubmit: (password: string) => Promise<{ success: boolean; message?: string }>;
  vault: Vault | null;
  loading?: boolean;
}

export const UnlockVaultModal: React.FC<UnlockVaultModalProps> = ({
  isOpen,
  onClose,
  onSubmit,
  vault,
  loading = false,
}) => {
  const { colors } = useUnifiedTheme();
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    if (!isOpen) {
      setPassword('');
      setError('');
      setShowPassword(false);
    }
  }, [isOpen]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    
    if (!password.trim()) {
      setError('Ingresa la contraseña del vault');
      return;
    }

    try {
      const result = await onSubmit(password.trim());
      if (result.success) {
        onClose();
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Contraseña incorrecta');
    }
  };

  if (!isOpen || !vault) return null;

  const colorScheme = VAULT_COLORS[vault.color];

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
        {/* Header con información del vault */}
        <div className="text-center mb-6">
          <div className="flex justify-center mb-4">
            <div 
              className={`w-16 h-16 rounded-full flex items-center justify-center ${colorScheme.bg}`}
            >
              <Lock className={`w-8 h-8 ${colorScheme.icon}`} />
            </div>
          </div>
          <h3 className="text-xl font-semibold mb-2" style={{ color: colors.textPrimary }}>
            Desbloquear Vault
          </h3>
          <p className="text-sm" style={{ color: colors.textSecondary }}>
            Ingresa la contraseña para acceder a "{vault.name}"
          </p>
          <div className="flex items-center justify-center mt-2 space-x-2">
            <div className={`w-3 h-3 rounded-full ${colorScheme.bg}`} />
            <span className="text-xs" style={{ color: colors.textMuted }}>
              {vault.password_count} contraseñas
            </span>
          </div>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="relative">
            <input
              type={showPassword ? "text" : "password"}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Contraseña del vault"
              className="w-full px-4 py-3 pr-12 rounded-lg border focus:outline-none focus:ring-2"
              style={{
                backgroundColor: colors.background,
                borderColor: error ? colors.error : colors.border,
                color: colors.textPrimary
              }}
              disabled={loading}
              autoFocus
              required
            />
            <button
              type="button"
              onClick={() => setShowPassword(!showPassword)}
              className="absolute right-3 top-1/2 transform -translate-y-1/2"
              style={{ color: colors.textMuted }}
              disabled={loading}
            >
              {showPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
            </button>
          </div>

          {error && (
            <div className="p-3 rounded-lg" style={{ backgroundColor: `${colors.error}20` }}>
              <p className="text-sm" style={{ color: colors.error }}>
                {error}
              </p>
            </div>
          )}

          <div className="flex gap-3">
            <button
              type="button"
              onClick={onClose}
              className="flex-1 px-4 py-2 rounded-lg border font-medium"
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
                backgroundColor: colors.primary,
                opacity: loading ? 0.7 : 1
              }}
              disabled={loading || !password.trim()}
            >
              {loading ? 'Desbloqueando...' : 'Desbloquear'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};