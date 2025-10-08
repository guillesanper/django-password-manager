import React from 'react';
import { 
  Key, 
  AlertTriangle, 
  Lock, 
  Clock, 
  Info 
} from 'lucide-react';
import { useUnifiedTheme } from '../UnifiedThemeProvider';
import { type SecurityIssue, securityService } from '../../services/securityService';

interface SecurityIssueCardProps {
  issue: SecurityIssue;
}

export const SecurityIssueCard: React.FC<SecurityIssueCardProps> = ({ issue }) => {
  const { colors } = useUnifiedTheme();
  
  const getIssueIcon = (type: SecurityIssue['type']) => {
    switch (type) {
      case 'weak_passwords': return Key;
      case 'breached_passwords': return AlertTriangle;
      case 'duplicate_passwords': return Lock;
      case 'old_passwords': return Clock;
      default: return Info;
    }
  };

  const Icon = getIssueIcon(issue.type);
  const severityColor = securityService.getSeverityColor(issue.severity);

  return (
    <div 
      className="rounded-lg p-4 border-l-4 transition-colors"
      style={{ 
        backgroundColor: colors.surface,
        borderLeftColor: severityColor
      }}
    >
      <div className="flex items-start space-x-3">
        <Icon className="w-5 h-5 mt-0.5" style={{ color: severityColor }} />
        <div className="flex-1">
          <div className="flex items-center justify-between">
            <p className="font-medium" style={{ color: colors.textPrimary }}>
              {issue.message}
            </p>
            <span 
              className="text-xs px-2 py-1 rounded-full capitalize"
              style={{
                backgroundColor: severityColor + '20',
                color: severityColor
              }}
            >
              {issue.severity}
            </span>
          </div>
        </div>
      </div>
    </div>
  );
};