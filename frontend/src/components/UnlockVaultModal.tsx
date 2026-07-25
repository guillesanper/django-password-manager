import React, { useState } from 'react';
import { Lock, Shield, AlertCircle, Eye, EyeOff, LogOut } from 'lucide-react';
import { useUnifiedTheme } from './UnifiedThemeProvider';

interface UnlockVaultModalProps {
  isOpen: boolean;
  onUnlock: (masterKey: string) => Promise<{ success: boolean; error?: string }>;
  onLogout: () => void;
  userName?: string;
}

/**
 * Modal de DESBLOQUEO (Fase 2, zero-knowledge). Distinto del de creación: aquí el usuario ya tiene
 * clave maestra pero la VaultKey no está en memoria (login/recarga/auto-bloqueo). Introduce la
 * maestra existente y `onUnlock` la deriva y desenvuelve la VaultKey en local. No es cerrable: sin
 * desbloquear no se pueden descifrar las contraseñas.
 */
export const UnlockVaultModal: React.FC<UnlockVaultModalProps> = ({
  isOpen,
  onUnlock,
  onLogout,
  userName = 'Usuario',
}) => {
  const { colors } = useUnifiedTheme();
  const [masterKey, setMasterKey] = useState('');
  const [showMasterKey, setShowMasterKey] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  if (!isOpen) return null;

  const handleSubmit = async () => {
    setError('');
    if (!masterKey.trim()) {
      setError('Introduce tu clave maestra');
      return;
    }

    setLoading(true);
    try {
      const result = await onUnlock(masterKey);
      if (result.success) {
        setMasterKey('');
      } else {
        setError(result.error || 'Contraseña maestra incorrecta');
      }
    } catch {
      setError('Error de conexión. Intenta de nuevo.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 flex items-center justify-center p-4 z-50">
      <div
        className="absolute inset-0"
        style={{
          backgroundColor: 'rgba(0, 0, 0, 0.4)',
          backdropFilter: 'blur(8px)',
          WebkitBackdropFilter: 'blur(8px)',
        }}
      />

      <div
        className="relative max-w-md w-full rounded-2xl shadow-2xl border"
        style={{
          backgroundColor: colors.surface,
          borderColor: colors.border,
          boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.25)',
        }}
      >
        <div className="p-8">
          <div className="text-center mb-6">
            <div className="flex items-center justify-center mb-4">
              <div className="p-3 rounded-full bg-gradient-to-r from-indigo-500 to-purple-600">
                <Shield className="w-8 h-8 text-white" />
              </div>
            </div>
            <h2 className="text-2xl font-bold mb-2" style={{ color: colors.textPrimary }}>
              Desbloquear bóveda
            </h2>
            <p className="text-sm" style={{ color: colors.textSecondary }}>
              Hola {userName}, introduce tu clave maestra para acceder a tus contraseñas.
            </p>
          </div>

          {error && (
            <div className="mb-4 p-3 rounded-lg border-l-4 bg-red-50 border-red-500">
              <div className="flex items-center">
                <AlertCircle className="w-4 h-4 text-red-500 mr-2" />
                <p className="text-sm text-red-700">{error}</p>
              </div>
            </div>
          )}

          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium mb-2" style={{ color: colors.textPrimary }}>
                Clave Maestra
              </label>
              <div className="relative">
                <Lock className="absolute left-3 top-3 w-5 h-5" style={{ color: colors.textMuted }} />
                <input
                  type={showMasterKey ? 'text' : 'password'}
                  value={masterKey}
                  autoFocus
                  onChange={(e) => {
                    setMasterKey(e.target.value);
                    setError('');
                  }}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' && !loading) handleSubmit();
                  }}
                  placeholder="Tu clave maestra"
                  className="w-full pl-10 pr-12 py-3 rounded-lg border transition-all duration-200 focus:outline-none focus:ring-2 focus:border-transparent"
                  style={{
                    backgroundColor: colors.surface,
                    borderColor: error ? colors.error : colors.border,
                    color: colors.textPrimary,
                  }}
                />
                <button
                  type="button"
                  onClick={() => setShowMasterKey(!showMasterKey)}
                  className="absolute right-3 top-3 p-1 rounded-md transition-colors"
                  style={{ color: colors.textMuted }}
                >
                  {showMasterKey ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
                </button>
              </div>
            </div>

            <button
              onClick={handleSubmit}
              disabled={loading || !masterKey}
              className="w-full py-3 px-4 rounded-lg font-semibold text-white transition-all duration-200 hover:scale-[1.02] disabled:opacity-50 disabled:cursor-not-allowed"
              style={{ backgroundColor: colors.primary }}
            >
              {loading ? (
                <span className="flex items-center justify-center">
                  <div className="animate-spin rounded-full h-4 w-4 border-2 border-transparent border-t-current mr-2"></div>
                  Desbloqueando...
                </span>
              ) : (
                'Desbloquear'
              )}
            </button>

            <button
              onClick={onLogout}
              disabled={loading}
              className="w-full py-2 px-4 rounded-lg font-medium border transition-all duration-200 flex items-center justify-center gap-2"
              style={{ borderColor: colors.border, color: colors.textSecondary, backgroundColor: 'transparent' }}
            >
              <LogOut className="w-4 h-4" />
              Cerrar sesión
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
