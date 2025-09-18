// components/account/AccountCard.tsx
import React from 'react';
import { Eye, Edit2, Trash2, Copy, ExternalLink, Shield, CheckSquare, Square, Lock, Folder } from 'lucide-react';
import { useUnifiedTheme } from '../../theme/UnifiedThemeProvider';
import { VAULT_COLORS } from '../../services/vaultService';

export interface PasswordAccount {
  id: number;
  website: string;
  username: string;
  encrypted_password: string;
  encryption_algorithm: string;
  salt: string;
  iv_or_nonce: string;
  encrypted_key: string;
  decrypted_password?: string;
  // NEW: Vault information
  vault_id?: number | null;
  vault_name?: string;
  vault_color?: 'blue' | 'green' | 'purple' | 'pink' | 'yellow' | 'red' | 'gray';
  vault_is_private?: boolean;
}

interface AccountCardProps {
  account: PasswordAccount;
  onUnlock: (accountId: number) => void;
  onEdit: (accountId: number) => void;
  onDelete: (accountId: number) => void;
  onCopy: (password: string) => void;
  isUnlocked: boolean;
  // Selection props
  isSelectionMode?: boolean;
  isSelected?: boolean;
  onToggleSelection?: (accountId: number) => void;
  onEnterSelectionMode?: (accountId: number) => void;
}

export const AccountCard: React.FC<AccountCardProps> = ({
  account,
  onUnlock,
  onEdit,
  onDelete,
  onCopy,
  isUnlocked,
  isSelectionMode = false,
  isSelected = false,
  onToggleSelection,
  onEnterSelectionMode
}) => {
  const { colors } = useUnifiedTheme();

  // Get vault color scheme if account has vault
  const vaultColorScheme = account.vault_color ? VAULT_COLORS[account.vault_color] : null;

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

  // Handle clicking on the card (but not on buttons)
  const handleCardClick = (e: React.MouseEvent) => {
    // Don't trigger if clicking on buttons or interactive elements
    const target = e.target as HTMLElement;
    const isButton = target.closest('button') || target.closest('a');
    
    if (isButton) {
      return; // Let the button handle its own click
    }

    if (isSelectionMode && onToggleSelection) {
      onToggleSelection(account.id);
    } else if (!isSelectionMode && onEnterSelectionMode) {
      onEnterSelectionMode(account.id);
    }
  };

  // Handle selection checkbox click
  const handleSelectionClick = (e: React.MouseEvent) => {
    e.stopPropagation(); // Prevent card click
    if (onToggleSelection) {
      onToggleSelection(account.id);
    }
  };

  // Get card styles based on selection state and vault
  const getCardStyles = () => {
    const baseStyles = { 
      backgroundColor: colors.surface,
      borderColor: colors.border,
      cursor: isSelectionMode ? 'pointer' : 'default'
    };

    if (isSelected) {
      return {
        ...baseStyles,
        borderColor: colors.primary,
        backgroundColor: `${colors.primary}08`, // Very light tint
        boxShadow: `0 0 0 1px ${colors.primary}40`
      };
    }

    // Add subtle vault-based styling
    if (vaultColorScheme && !isSelected) {
      return {
        ...baseStyles,
        borderTopColor: vaultColorScheme.border,
        borderTopWidth: '2px'
      };
    }

    return baseStyles;
  };

  // Get shadow color for vault
  const getShadowColor = (color: string) => {
    const colorMap: Record<string, string> = {
      blue: 'rgba(59, 130, 246, 0.1)',
      green: 'rgba(16, 185, 129, 0.1)',
      purple: 'rgba(139, 92, 246, 0.1)',
      pink: 'rgba(236, 72, 153, 0.1)',
      yellow: 'rgba(245, 158, 11, 0.1)',
      red: 'rgba(239, 68, 68, 0.1)',
      gray: 'rgba(107, 114, 128, 0.1)'
    };
    return colorMap[color] || colorMap.blue;
  };

  return (
    <div 
      className="account-card"
      style={{
        ...getCardStyles(),
        boxShadow: vaultColorScheme && !isSelected 
          ? `0 4px 15px -3px ${getShadowColor(account.vault_color!)}, 0 2px 6px -2px ${getShadowColor(account.vault_color!)}`
          : undefined
      }}
      onClick={handleCardClick}
    >
      {/* Vault color bar at the top */}
      {vaultColorScheme && (
        <div 
          className="absolute top-0 left-0 right-0 h-1"
          style={{ backgroundColor: vaultColorScheme.icon }}
        />
      )}

      {/* Selection checkbox - only visible in selection mode */}
      {isSelectionMode && (
        <div 
          className="absolute top-3 left-3 z-10"
          onClick={handleSelectionClick}
        >
          <button
            className="w-6 h-6 rounded border-2 flex items-center justify-center transition-all"
            style={{
              borderColor: isSelected ? colors.primary : colors.border,
              backgroundColor: isSelected ? colors.primary : 'transparent',
              color: isSelected ? 'white' : colors.textSecondary
            }}
          >
            {isSelected ? (
              <CheckSquare className="w-4 h-4" />
            ) : (
              <Square className="w-4 h-4" />
            )}
          </button>
        </div>
      )}

      <div className="account-card-header">
        <div 
          className="account-card-info"
          style={{ 
            paddingLeft: isSelectionMode ? '2rem' : '0', // Add space for checkbox
            paddingTop: vaultColorScheme ? '0.5rem' : '0' // Add space for vault bar
          }}
        >
          <div 
            className="account-card-avatar"
            style={{ 
              backgroundColor: vaultColorScheme 
                ? `${vaultColorScheme.bg}20` 
                : `${colors.primary}20` 
            }}
          >
            <img
              src={getFaviconUrl(account.website)}
              alt={account.website}
              style={{ width: '24px', height: '24px' }}
              onError={(e) => {
                (e.target as HTMLImageElement).src = 'data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="m9 12 2 2 4-4"/></svg>';
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
        
        {/* Actions - hidden in selection mode or shown with reduced opacity */}
        <div 
          className="account-card-actions"
          style={{ 
            opacity: isSelectionMode ? 0.3 : undefined,
            pointerEvents: isSelectionMode ? 'none' : 'auto'
          }}
        >
          {!isUnlocked && (
            <button
              onClick={() => onUnlock(account.id)}
              className="account-card-action-button"
              style={{ color: vaultColorScheme ? vaultColorScheme.icon : colors.primary }}
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
                style={{ 
                  color: vaultColorScheme ? vaultColorScheme.icon : colors.primary,
                  opacity: isSelectionMode ? 0.5 : 1,
                  pointerEvents: isSelectionMode ? 'none' : 'auto'
                }}
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
              style={{ 
                backgroundColor: vaultColorScheme ? vaultColorScheme.icon : colors.primary,
                opacity: isSelectionMode ? 0.5 : 1,
                pointerEvents: isSelectionMode ? 'none' : 'auto'
              }}
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
              backgroundColor: vaultColorScheme ? `${vaultColorScheme.bg}20` : `${colors.info}20`,
              color: vaultColorScheme ? vaultColorScheme.text : colors.info,
              padding: '0.25rem 0.5rem',
              borderRadius: '0.25rem',
              fontSize: '0.75rem',
              fontWeight: '500'
            }}
          >
            {account.encryption_algorithm}
          </span>
        </div>
        
        <div className="flex items-center space-x-2">
          {/* Vault badge */}
          {account.vault_name && vaultColorScheme && (
            <div 
              className="flex items-center space-x-1 px-2 py-1 rounded-full"
              style={{ 
                backgroundColor: `${vaultColorScheme.bg}15`,
                color: vaultColorScheme.text,
                border: `1px solid ${vaultColorScheme.border}`
              }}
            >
              {account.vault_is_private ? (
                <Lock className="w-3 h-3" />
              ) : (
                <Folder className="w-3 h-3" />
              )}
              <span style={{ fontSize: '0.75rem', fontWeight: '500' }}>
                {account.vault_name}
              </span>
            </div>
          )}
          
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