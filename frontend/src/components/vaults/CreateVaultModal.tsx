import React, { useState, useEffect } from 'react';
import { X, Lock, Unlock, Eye, EyeOff } from 'lucide-react';
import { useUnifiedTheme } from '../UnifiedThemeProvider';
import { type CreateVaultData,VAULT_COLORS } from '../../services/vaultService';

// Modal para crear vault
interface CreateVaultModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSubmit: (vaultData: CreateVaultData) => Promise<{ success: boolean; message?: string }>;
  loading?: boolean;
}

export const CreateVaultModal: React.FC<CreateVaultModalProps> = ({
  isOpen,
  onClose,
  onSubmit,
  loading = false
}) => {
  const { colors } = useUnifiedTheme();
  const [formData, setFormData] = useState<CreateVaultData>({
    name: '',
    description: '',
    color: 'blue',
    is_private: false,
    vault_password: ''
  });
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    if (!isOpen) {
      setFormData({
        name: '',
        description: '',
        color: 'blue',
        is_private: false,
        vault_password: ''
      });
      setError('');
      setShowPassword(false);
    }
  }, [isOpen]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    
    if (!formData.name.trim()) {
      setError('El nombre del vault es requerido');
      return;
    }
    
    if (formData.is_private && !formData.vault_password) {
      setError('Los vaults privados requieren una contraseña');
      return;
    }
    
    if (formData.is_private && formData.vault_password && formData.vault_password.length < 6) {
      setError('La contraseña del vault debe tener al menos 6 caracteres');
      return;
    }

    try {
      const result = await onSubmit(formData);
      if (result.success) {
        onClose();
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Error al crear el vault');
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
        {/* Header */}
        <div className="flex items-center justify-between mb-6">
          <h3 className="text-xl font-semibold" style={{ color: colors.textPrimary }}>
            Crear Nuevo Vault
          </h3>
          <button
            onClick={onClose}
            className="p-2 rounded-lg transition-colors"
            style={{ color: colors.textMuted }}
            disabled={loading}
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          {/* Nombre */}
          <div>
            <label className="block text-sm font-medium mb-2" style={{ color: colors.textSecondary }}>
              Nombre del Vault *
            </label>
            <input
              type="text"
              value={formData.name}
              onChange={(e) => setFormData(prev => ({ ...prev, name: e.target.value }))}
              placeholder="Ej: Trabajo, Personal, Redes Sociales..."
              className="w-full px-3 py-2 rounded-lg border focus:outline-none focus:ring-2"
              style={{
                backgroundColor: colors.background,
                borderColor: colors.border,
                color: colors.textPrimary
              }}
              disabled={loading}
              maxLength={100}
              required
            />
          </div>

          {/* Descripción */}
          <div>
            <label className="block text-sm font-medium mb-2" style={{ color: colors.textSecondary }}>
              Descripción (opcional)
            </label>
            <textarea
              value={formData.description}
              onChange={(e) => setFormData(prev => ({ ...prev, description: e.target.value }))}
              placeholder="Describe para qué usarás este vault..."
              rows={3}
              className="w-full px-3 py-2 rounded-lg border focus:outline-none focus:ring-2 resize-none"
              style={{
                backgroundColor: colors.background,
                borderColor: colors.border,
                color: colors.textPrimary
              }}
              disabled={loading}
              maxLength={500}
            />
          </div>

          {/* Color */}
          <div>
            <label className="block text-sm font-medium mb-2" style={{ color: colors.textSecondary }}>
              Color
            </label>
            <div className="flex gap-2 flex-wrap">
              {Object.entries(VAULT_COLORS).map(([colorKey]) => (
                <button
                  key={colorKey}
                  type="button"
                  onClick={() => setFormData(prev => ({ ...prev, color: colorKey as any }))}
                  className={`
                    w-8 h-8 rounded-full border-2 transition-all duration-200
                    ${formData.color === colorKey ? 'ring-2 ring-offset-2 scale-110' : 'hover:scale-105'}
                  `}
                  style={{
                    backgroundColor: colorKey === 'blue' ? '#3b82f6' :
                                   colorKey === 'green' ? '#10b981' :
                                   colorKey === 'purple' ? '#8b5cf6' :
                                   colorKey === 'pink' ? '#ec4899' :
                                   colorKey === 'yellow' ? '#f59e0b' :
                                   colorKey === 'red' ? '#ef4444' : '#6b7280',
                    borderColor: formData.color === colorKey ? colors.primary : colors.border,
                  }}
                  disabled={loading}
                  title={colorKey.charAt(0).toUpperCase() + colorKey.slice(1)}
                />
              ))}
            </div>
          </div>

          {/* Privacidad */}
          <div>
            <label className="flex items-center space-x-3 cursor-pointer">
              <input
                type="checkbox"
                checked={formData.is_private}
                onChange={(e) => setFormData(prev => ({ 
                  ...prev, 
                  is_private: e.target.checked,
                  vault_password: e.target.checked ? prev.vault_password : ''
                }))}
                className="w-4 h-4 rounded border"
                style={{
                  color: colors.primary,
                  borderColor: colors.border
                }}
                disabled={loading}
              />
              <span className="flex items-center space-x-2">
                {formData.is_private ? (
                  <Lock className="w-4 h-4" style={{ color: colors.textMuted }} />
                ) : (
                  <Unlock className="w-4 h-4" style={{ color: colors.textMuted }} />
                )}
                <span style={{ color: colors.textSecondary }}>
                  Hacer vault privado (requiere contraseña adicional)
                </span>
              </span>
            </label>
          </div>

          {/* Contraseña del vault (solo si es privado) */}
          {formData.is_private && (
            <div>
              <label className="block text-sm font-medium mb-2" style={{ color: colors.textSecondary }}>
                Contraseña del Vault *
              </label>
              <div className="relative">
                <input
                  type={showPassword ? "text" : "password"}
                  value={formData.vault_password}
                  onChange={(e) => setFormData(prev => ({ ...prev, vault_password: e.target.value }))}
                  placeholder="Mínimo 6 caracteres..."
                  className="w-full px-3 py-2 pr-10 rounded-lg border focus:outline-none focus:ring-2"
                  style={{
                    backgroundColor: colors.background,
                    borderColor: colors.border,
                    color: colors.textPrimary
                  }}
                  disabled={loading}
                  minLength={6}
                  required={formData.is_private}
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-1/2 transform -translate-y-1/2"
                  style={{ color: colors.textMuted }}
                  disabled={loading}
                >
                  {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
              <p className="text-xs mt-1" style={{ color: colors.textMuted }}>
                Esta contraseña será requerida cada vez que accedas al vault
              </p>
            </div>
          )}

          {/* Error */}
          {error && (
            <div className="p-3 rounded-lg" style={{ backgroundColor: `${colors.error}20` }}>
              <p className="text-sm" style={{ color: colors.error }}>
                {error}
              </p>
            </div>
          )}

          {/* Botones */}
          <div className="flex gap-3 pt-4">
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
              disabled={loading}
            >
              {loading ? 'Creando...' : 'Crear Vault'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};