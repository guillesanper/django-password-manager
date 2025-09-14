import React, { useState } from 'react';
import { Eye, Edit2, Trash2, Copy, ExternalLink, Shield, Lock, Folder } from 'lucide-react';
import { useUnifiedTheme } from '../../theme/UnifiedThemeProvider';
import { VAULT_COLORS, type Vault } from '../../services/vaultService';
import { type PasswordAccount } from '../../components/account/AccountCard';

interface VaultPasswordCardProps {
  account: PasswordAccount;
  vault: Vault;
  onUnlock: (accountId: number) => void;
  onEdit: (accountId: number) => void;
  onDelete: (accountId: number) => void;
  onCopy: (password: string) => void;
  isUnlocked: boolean;
}

export const VaultPasswordCard: React.FC<VaultPasswordCardProps> = ({
  account,
  vault,
  onUnlock,
  onEdit,
  onDelete,
  onCopy,
  isUnlocked
}) => {
  const { colors } = useUnifiedTheme();
  const [isHovered, setIsHovered] = useState(false);
  const colorScheme = VAULT_COLORS[vault.color];

  const handleCopy = async () => {
    if (account.decrypted_password) {
      try {
        await navigator.clipboard.writeText(account.decrypted_password);
        onCopy(account.decrypted_password);
      } catch (err) {
        console.error('Failed to copy password:', err);
      }
    }
  };

  const getFaviconUrl = (website: string) => {
    const domain = website.replace(/^https?:\/\//, '').replace(/^www\./, '');
    return `https://www.google.com/s2/favicons?domain=${domain}&sz=32`;
  };

  // Color de sombra basado en el color del vault
  const getShadowColor = (color: string) => {
    const colorMap: Record<string, string> = {
      blue: 'rgba(59, 130, 246, 0.3)',
      green: 'rgba(16, 185, 129, 0.3)',
      purple: 'rgba(139, 92, 246, 0.3)',
      pink: 'rgba(236, 72, 153, 0.3)',
      yellow: 'rgba(245, 158, 11, 0.3)',
      red: 'rgba(239, 68, 68, 0.3)',
      gray: 'rgba(107, 114, 128, 0.3)'
    };
    return colorMap[color] || colorMap.blue;
  };

  return (
    <div
      className="account-card relative transition-all duration-200"
      style={{
        backgroundColor: colors.surface,
        borderColor: isHovered ? colorScheme.border : colors.border,
        boxShadow: isHovered 
          ? `0 8px 25px -5px ${getShadowColor(vault.color)}, 0 4px 10px -3px ${getShadowColor(vault.color)}`
          : `0 4px 15px -3px ${getShadowColor(vault.color)}, 0 2px 6px -2px ${getShadowColor(vault.color)}`
      }}
      onMouseEnter={() => setIsHovered(true)}
      onMouseLeave={() => setIsHovered(false)}
    >
      {/* Barra superior con color del vault */}
      <div 
        className="absolute top-0 left-0 right-0 h-1"
        style={{ backgroundColor: colorScheme.bg }}
      />

      <div className="account-card-header">
        <div className="account-card-info">
          <div 
            className="account-card-avatar"
            style={{ backgroundColor: `${colorScheme.bg}20` }}
          >
            <img
              src={getFaviconUrl(account.website)}
              alt={account.website}
              style={{ width: '24px', height: '24px' }}
              onError={(e) => {
                // Fallback icon based on vault type
                const fallbackIcon = vault.is_private ? 
                  'data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><circle cx="12" cy="16" r="1"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>' :
                  'data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg>';
                (e.target as HTMLImageElement).src = fallbackIcon;
              }}
            />
          </div>
          <div className="account-card-details">
            <h3 
              className="account-card-title"
              style={{ color: colors.textPrimary }}
            >
              {account.website}
            </h3>
            <div 
              className="account-card-username"
              style={{ color: colors.textSecondary }}
            >
              {account.username}
            </div>
          </div>
        </div>
        <div className="account-card-actions">
          {!isUnlocked && (
            <button
              onClick={() => onUnlock(account.id)}
              className="account-card-action-button"
              style={{ color: colorScheme.border }}
              title="Desbloquear contraseña"
            >
              <Eye className="w-4 h-4" />
            </button>
          )}
          <button
            onClick={() => onEdit(account.id)}
            className="account-card-action-button"
            style={{ color: colors.textSecondary }}
            title="Editar cuenta"
          >
            <Edit2 className="w-4 h-4" />
          </button>
          <button
            onClick={() => onDelete(account.id)}
            className="account-card-action-button"
            style={{ color: colors.error }}
            title="Eliminar cuenta"
          >
            <Trash2 className="w-4 h-4" />
          </button>
          <a
            href={`https://${account.website}`}
            target="_blank"
            rel="noopener noreferrer"
            className="account-card-action-button"
            style={{ color: colors.textSecondary }}
            title="Visitar sitio web"
          >
            <ExternalLink className="w-4 h-4" />
          </a>
        </div>
      </div>

      <div className="account-card-body">
        {isUnlocked && account.decrypted_password ? (
          <div className="account-card-password">
            <div className="account-card-label" style={{ color: colors.textPrimary }}>
              Contraseña:
            </div>
            <div className="account-card-password-controls">
              <div 
                className="account-card-password-display"
                style={{ 
                  backgroundColor: colors.background,
                  borderColor: colors.border,
                  color: colors.textPrimary
                }}
              >
                {'•'.repeat(account.decrypted_password.length)}
              </div>
              <button
                onClick={handleCopy}
                className="account-card-control-button"
                style={{ color: colorScheme.bg }}
                title="Copiar contraseña"
              >
                <Copy className="w-4 h-4" />
              </button>
            </div>
          </div>
        ) : (
          <div className="account-card-password">
            <button
              onClick={() => onUnlock(account.id)}
              className="account-card-unlock-button"
              style={{ backgroundColor: colors.primary }}
            >
              <Eye className="w-4 h-4" />
              Desbloquear Contraseña
            </button>
          </div>
        )}
      </div>

      <div className="account-card-meta">
        <div className="account-card-algorithm">
          <span 
            style={{ 
              backgroundColor: `${colorScheme.bg}20`,
              color: colorScheme.bg,
              padding: '0.25rem 0.5rem',
              borderRadius: '0.25rem',
              fontSize: '0.75rem',
              fontWeight: '500'
            }}
          >
            {account.encryption_algorithm}
          </span>
        </div>
        
        {/* Badge del vault con icono */}
        <div className="flex items-center space-x-2">
          <div 
            className="flex items-center space-x-1 px-2 py-1 rounded-full"
            style={{ 
              backgroundColor: `${colorScheme.bg}15`,
              color: colorScheme.bg
            }}
          >
            {vault.is_private ? (
              <Lock className="w-3 h-3" />
            ) : (
              <Folder className="w-3 h-3" />
            )}
            <span style={{ fontSize: '0.75rem', fontWeight: '500' }}>
              {vault.name}
            </span>
          </div>
          
          <div className="account-card-security">
            <Shield className="w-3 h-3" style={{ color: colors.success }} />
            <span style={{ color: colors.textSecondary }}>
              Seguro
            </span>
          </div>
        </div>
      </div>
    </div>
  );
};