import React from 'react';
import { CheckCircle } from 'lucide-react';
import { useUnifiedTheme } from '../UnifiedThemeProvider';

interface SecurityRecommendationsProps {
  recommendations: string[];
}

export const SecurityRecommendations: React.FC<SecurityRecommendationsProps> = ({
  recommendations
}) => {
  const { colors } = useUnifiedTheme();

  if (recommendations.length === 0) return null;

  return (
    <div 
      className="rounded-lg p-6"
      style={{ backgroundColor: colors.surface }}
    >
      <h2 className="text-xl font-semibold mb-4" style={{ color: colors.textPrimary }}>
        Recomendaciones
      </h2>
      <ul className="space-y-2">
        {recommendations.map((recommendation, index) => (
          <li key={index} className="flex items-start space-x-2">
            <CheckCircle className="w-5 h-5 mt-0.5 flex-shrink-0" style={{ color: colors.success }} />
            <span style={{ color: colors.textSecondary }}>{recommendation}</span>
          </li>
        ))}
      </ul>
    </div>
  );
};