import React from 'react';
import { useUnifiedTheme } from '../UnifiedThemeProvider';

interface SecurityScoreCardProps {
  score: number;
  grade: string;
  description: string;
  gradeColor: string;
}

export const SecurityScoreCard: React.FC<SecurityScoreCardProps> = ({
  score,
  grade,
  description,
  gradeColor
}) => {
  const { colors } = useUnifiedTheme();

  return (
    <div 
      className="rounded-lg p-6 text-center"
      style={{ backgroundColor: colors.surface }}
    >
      <h2 className="text-xl font-semibold mb-2" style={{ color: colors.textPrimary }}>
        Puntuación General de Seguridad
      </h2>
      <div className="flex items-center justify-center space-x-4">
        <div 
          className="text-6xl font-bold"
          style={{ color: gradeColor }}
        >
          {grade}
        </div>
        <div className="text-left">
          <div className="text-3xl font-bold" style={{ color: colors.textPrimary }}>
            {score}/100
          </div>
          <div style={{ color: gradeColor }}>
            {description}
          </div>
        </div>
      </div>
    </div>
  );
};