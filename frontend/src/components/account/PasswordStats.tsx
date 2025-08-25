// components/account/PasswordStats.tsx
import React from 'react';
import { Shield, Lock, Unlock, AlertTriangle } from 'lucide-react';
import { useUnifiedTheme } from '../../theme/UnifiedThemeProvider';
import { type PasswordAccount } from './AccountCard';

interface PasswordStatsProps {
  accounts: PasswordAccount[];
}

export const PasswordStats: React.FC<PasswordStatsProps> = ({ accounts }) => {
  const { colors } = useUnifiedTheme();

  const stats = React.useMemo(() => {
    const total = accounts.length;
    const unlocked = accounts.filter(acc => acc.decrypted_password).length;
    const locked = total - unlocked;
    
    // Count encryption algorithms
    const encryptionCounts = accounts.reduce((acc, account) => {
      acc[account.encryption_algorithm] = (acc[account.encryption_algorithm] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);

    const strongEncryption = accounts.filter(acc => 
      acc.encryption_algorithm === 'AES-256' || acc.encryption_algorithm === 'ChaCha20'
    ).length;

    return {
      total,
      unlocked,
      locked,
      strongEncryption,
      encryptionCounts
    };
  }, [accounts]);

  const statCards = [
    {
      icon: Shield,
      label: 'Total de Contraseñas',
      value: stats.total,
      color: colors.primary,
      bgColor: `${colors.primary}20`
    },
    {
      icon: Unlock,
      label: 'Desbloqueadas',
      value: stats.unlocked,
      color: colors.success,
      bgColor: `${colors.success}20`
    },
    {
      icon: Lock,
      label: 'Bloqueadas',
      value: stats.locked,
      color: colors.warning,
      bgColor: `${colors.warning}20`
    },
    {
      icon: AlertTriangle,
      label: 'Cifrado Fuerte',
      value: stats.strongEncryption,
      color: colors.info,
      bgColor: `${colors.info}20`
    }
  ];

  return (
    <div className="password-stats-container">
      <div className="password-stats-grid">
        {statCards.map((stat, index) => {
          const IconComponent = stat.icon;
          return (
            <div
              key={index}
              className="password-stat-card"
              style={{ 
                backgroundColor: colors.surface,
                borderColor: colors.border
              }}
            >
              <div className="password-stat-content">
                <div className="password-stat-info">
                  <p 
                    className="password-stat-label"
                    style={{ color: colors.textSecondary }}
                  >
                    {stat.label}
                  </p>
                  <h3 
                    className="password-stat-value"
                    style={{ color: colors.textPrimary }}
                  >
                    {stat.value}
                  </h3>
                </div>
                <div 
                  className="password-stat-icon"
                  style={{ backgroundColor: stat.bgColor }}
                >
                  <IconComponent 
                    className="w-6 h-6"
                    style={{ color: stat.color }}
                  />
                </div>
              </div>
            </div>
          );
        })}
      </div>
      
      {/* Encryption breakdown */}
      {Object.keys(stats.encryptionCounts).length > 0 && (
        <div 
          className="password-encryption-breakdown"
          style={{ 
            backgroundColor: colors.surface,
            borderColor: colors.border
          }}
        >
          <h4 style={{ color: colors.textPrimary }}>
            Algoritmos de Cifrado
          </h4>
          <div className="password-encryption-list">
            {Object.entries(stats.encryptionCounts).map(([algorithm, count]) => (
              <div key={algorithm} className="password-encryption-item">
                <span 
                  className="password-encryption-name"
                  style={{ color: colors.textPrimary }}
                >
                  {algorithm}
                </span>
                <span 
                  className="password-encryption-count"
                  style={{ 
                    backgroundColor: `${colors.primary}20`,
                    color: colors.primary 
                  }}
                >
                  {count}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};