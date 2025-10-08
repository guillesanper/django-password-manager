import React from 'react';
import { type PasswordAnalysis } from '../../services/securityService';

interface StrengthProgressBarProps {
  strength: PasswordAnalysis['strength'];
  entropy: number;
  className?: string;
}

export const StrengthProgressBar: React.FC<StrengthProgressBarProps> = ({ 
  strength, 
  entropy, 
  className = '' 
}) => {
  return (
    <div className={`space-y-2 ${className}`}>
      <div className="flex justify-between items-center">
        <span className="text-sm font-medium" style={{ color: strength.color }}>
          {strength.label}
        </span>
        <span className="text-xs" style={{ color: strength.color }}>
          {entropy.toFixed(1)} bits
        </span>
      </div>
      <div className="w-full bg-gray-200 rounded-full h-2">
        <div 
          className="h-2 rounded-full transition-all duration-300"
          style={{ 
            backgroundColor: strength.color,
            width: `${strength.score}%`
          }}
        />
      </div>
    </div>
  );
};