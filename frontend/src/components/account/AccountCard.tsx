// components/account/AccountCard.tsx
import React from 'react';
import { Eye, Edit2, Trash2, Copy, ExternalLink, Shield } from 'lucide-react';
import { useUnifiedTheme } from '../../theme/UnifiedThemeProvider';

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
}

interface AccountCardProps {
  account: PasswordAccount;
  onUnlock: (accountId: number) => void;
  onEdit: (accountId: number) => void;
  onDelete: (accountId: number) => void;
  onCopy: (password: string) => void;
  isUnlocked: boolean;
}

export const AccountCard: React.FC<AccountCardProps> = ({
  account,
  onUnlock,
  onEdit,
  onDelete,
  onCopy,
  isUnlocked
}) => {
  const { colors } = useUnifiedTheme();

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

  return (
    <div 
      className="account-card"
      style={{ 
        backgroundColor: colors.surface,
        borderColor: colors.border
      }}
    >
      <div className="account-card-header">
        <div className="account-card-info">
          <div 
            className="account-card-avatar"
            style={{ backgroundColor: `${colors.primary}20` }}
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
        <div className="account-card-actions">
          {!isUnlocked && (
            <button
              onClick={() => onUnlock(account.id)}
              className="account-card-action-button"
              style={{ color: colors.primary }}
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
                style={{ color: colors.primary }}
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
              backgroundColor: `${colors.info}20`,
              color: colors.info,
              padding: '0.25rem 0.5rem',
              borderRadius: '0.25rem',
              fontSize: '0.75rem',
              fontWeight: '500'
            }}
          >
            {account.encryption_algorithm}
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
  );
};