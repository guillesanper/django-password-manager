import React from 'react';
import { TrendingUp, TrendingDown } from 'lucide-react';
import { useUnifiedTheme } from '../UnifiedThemeProvider';

interface QuickStatCardProps {
  title: string;
  value: number | string;
  icon: React.ComponentType<{ className?: string }>;
  color: string;
  trend?: 'up' | 'down' | 'neutral';
  subtitle?: string;
}

export const QuickStatCard: React.FC<QuickStatCardProps> = ({ 
  title, 
  value, 
  icon: Icon, 
  color, 
  trend,
  subtitle 
}) => {
  const { colors } = useUnifiedTheme();
  
  const getTrendIcon = () => {
    if (trend === 'up') return <TrendingUp className="security-quick-stat-trend-icon" style={{ color: colors.success }} />;
    if (trend === 'down') return <TrendingDown className="security-quick-stat-trend-icon" style={{ color: colors.error }} />;
    return null;
  };

  return (
    <div className="security-quick-stat-card">
      <div className="security-quick-stat-content">
        <div className="security-quick-stat-info">
          <p className="security-quick-stat-title">{title}</p>
          <p className="security-quick-stat-value">{value}</p>
          {subtitle && (
            <div className="security-quick-stat-subtitle">
              {getTrendIcon()}
              <span>{subtitle}</span>
            </div>
          )}
        </div>
        <div className="security-quick-stat-icon-container" style={{ backgroundColor: color }}>
          <Icon className="security-quick-stat-icon" />
        </div>
      </div>
    </div>
  );
};