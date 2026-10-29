// Modal para gestionar vault (editar, eliminar, etc.)

import React from 'react';
import { X, Lock, Unlock, Folder, Settings2 } from 'lucide-react';
import { useUnifiedTheme } from '../UnifiedThemeProvider';
import { VAULT_COLORS,type Vault } from '../../services/vaultService';

interface ManageVaultModalProps {
  isOpen: boolean;
  onClose: () => void;
  vault: Vault | null;
  onEdit: (vault: Vault) => void;
  onDelete: (vault: Vault) => void;
  onChangePrivacy: (vault: Vault) => void;
  onChangePassword: (vault: Vault) => void;
}

export const ManageVaultModal: React.FC<ManageVaultModalProps> = ({
  isOpen,
  onClose,
  vault,
  onEdit,
  onDelete,
  onChangePrivacy,
  onChangePassword
}) => {
  const { colors } = useUnifiedTheme();

  if (!isOpen || !vault) return null;

  const colorScheme = VAULT_COLORS[vault.color];

  const handleAction = (action: () => void) => {
    onClose();
    action();
  };

  return (
    <div className="fixed inset-0 flex items-center justify-center p-4 z-50">
      <div 
        className="absolute inset-0"
        style={{
          backgroundColor: 'rgba(0, 0, 0, 0.4)',
          backdropFilter: 'blur(8px)',
        }}
        onClick={onClose}
      />
      <div 
        className="relative max-w-md w-full rounded-2xl shadow-2xl border p-6"
        onClick={(e) => e.stopPropagation()}
        style={{ 
          backgroundColor: colors.surface,
          borderColor: colors.border,
        }}
      >
        {/* Header del vault */}
        <div className="text-center mb-6">
          <div className="flex justify-center mb-4">
            <div 
              className={`w-16 h-16 rounded-full flex items-center justify-center ${colorScheme.bg}`}
            >
              {vault.is_private ? (
                <Lock className={`w-8 h-8 ${colorScheme.icon}`} />
              ) : (
                <Folder className={`w-8 h-8 ${colorScheme.icon}`} />
              )}
            </div>
          </div>
          <h3 className="text-xl font-semibold mb-2" style={{ color: colors.textPrimary }}>
            {vault.name}
          </h3>
          {vault.description && (
            <p className="text-sm mb-2" style={{ color: colors.textSecondary }}>
              {vault.description}
            </p>
          )}
          <div className="flex items-center justify-center space-x-4 text-xs" style={{ color: colors.textMuted }}>
            <span>{vault.password_count} contraseñas</span>
            <span>•</span>
            <span>{vault.is_private ? 'Privado' : 'Público'}</span>
          </div>
        </div>

        {/* Acciones */}
        <div className="space-y-2">
          <button
            onClick={() => handleAction(() => onEdit(vault))}
            className="w-full text-left px-4 py-3 rounded-lg transition-colors flex items-center space-x-3"
            style={{
              backgroundColor: colors.background,
              color: colors.textPrimary
            }}
            onMouseEnter={(e) => {
              e.currentTarget.style.backgroundColor = colors.surfaceHover;
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.backgroundColor = colors.background;
            }}
          >
            <Settings2 className="w-4 h-4" />
            <span>Editar vault</span>
          </button>

          {vault.is_private && (
            <button
              onClick={() => handleAction(() => onChangePassword(vault))}
              className="w-full text-left px-4 py-3 rounded-lg transition-colors flex items-center space-x-3"
              style={{
                backgroundColor: colors.background,
                color: colors.textPrimary
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.backgroundColor = colors.surfaceHover;
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.backgroundColor = colors.background;
              }}
            >
              <Lock className="w-4 h-4" />
              <span>Cambiar contraseña</span>
            </button>
          )}

          <button
            onClick={() => handleAction(() => onChangePrivacy(vault))}
            className="w-full text-left px-4 py-3 rounded-lg transition-colors flex items-center space-x-3"
            style={{
              backgroundColor: colors.background,
              color: colors.textPrimary
            }}
            onMouseEnter={(e) => {
              e.currentTarget.style.backgroundColor = colors.surfaceHover;
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.backgroundColor = colors.background;
            }}
          >
            {vault.is_private ? <Unlock className="w-4 h-4" /> : <Lock className="w-4 h-4" />}
            <span>{vault.is_private ? 'Hacer público' : 'Hacer privado'}</span>
          </button>

          <hr style={{ borderColor: colors.border }} />

          <button
            onClick={() => handleAction(() => onDelete(vault))}
            className="w-full text-left px-4 py-3 rounded-lg transition-colors flex items-center space-x-3"
            style={{
              backgroundColor: colors.background,
              color: colors.error
            }}
            onMouseEnter={(e) => {
              e.currentTarget.style.backgroundColor = `${colors.error}10`;
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.backgroundColor = colors.background;
            }}
          >
            <X className="w-4 h-4" />
            <span>Eliminar vault</span>
          </button>
        </div>

        {/* Botón cerrar */}
        <div className="mt-6">
          <button
            onClick={onClose}
            className="modal-btn modal-btn--secondary w-full"
          >
            Cerrar
          </button>
        </div>
      </div>
    </div>
  );
};