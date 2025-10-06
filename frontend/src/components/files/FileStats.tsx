// components/files/FileStats.tsx
import React from 'react';
import { File, HardDrive, Shield, Clock } from 'lucide-react';
import { useUnifiedTheme } from '../UnifiedThemeProvider';
import { type EncryptedFile } from '../../services/fileService';

interface FileStatsProps {
  files: EncryptedFile[];
}

export const FileStats: React.FC<FileStatsProps> = ({ files }) => {
  const { colors } = useUnifiedTheme();

  // Calcular estadísticas
  const totalFiles = files.length;
  
  // Contar archivos por algoritmo
  const algorithmCounts = files.reduce((acc, file) => {
    acc[file.algorithm] = (acc[file.algorithm] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);

  // Archivos recientes (últimos 7 días)
  const oneWeekAgo = new Date();
  oneWeekAgo.setDate(oneWeekAgo.getDate() - 7);
  const recentFiles = files.filter(file => 
    new Date(file.uploaded_at) > oneWeekAgo
  ).length;

  // Algoritmo más usado
  const mostUsedAlgorithm = Object.entries(algorithmCounts)
    .sort(([,a], [,b]) => b - a)[0]?.[0] || 'N/A';

  const stats = [
    {
      title: "Total de Archivos",
      value: totalFiles.toString(),
      icon: File,
      color: "bg-blue-500"
    },
    {
      title: "Algoritmos Usados",
      value: Object.keys(algorithmCounts).length.toString(),
      icon: Shield,
      color: "bg-green-500"
    },
    {
      title: "Subidos Esta Semana",
      value: recentFiles.toString(),
      icon: Clock,
      color: "bg-purple-500"
    },
    {
      title: "Algoritmo Principal",
      value: mostUsedAlgorithm,
      icon: HardDrive,
      color: "bg-orange-500"
    }
  ];

  return (
    <div className="file-stats-container">
      <h2 className="file-stats-title" style={{ color: colors.textPrimary }}>
        Estadísticas de Archivos
      </h2>
      <div className="file-stats-grid">
        {stats.map((stat, index) => {
          const Icon = stat.icon;
          return (
            <div 
              key={index}
              className="file-stats-card"
              style={{ 
                backgroundColor: colors.surface,
                borderColor: colors.border
              }}
            >
              <div className="file-stats-card-content">
                <div>
                  <p className="file-stats-card-title" style={{ color: colors.textSecondary }}>
                    {stat.title}
                  </p>
                  <p className="file-stats-card-value" style={{ color: colors.textPrimary }}>
                    {stat.value}
                  </p>
                </div>
                <div className={`file-stats-card-icon ${stat.color}`}>
                  <Icon className="w-6 h-6 text-white" />
                </div>
              </div>
            </div>
          );
        })}
      </div>
      
      {/* Distribución de algoritmos */}
      {Object.keys(algorithmCounts).length > 0 && (
        <div 
          className="file-stats-algorithms"
          style={{ 
            backgroundColor: colors.surface,
            borderColor: colors.border
          }}
        >
          <h3 className="file-stats-algorithms-title" style={{ color: colors.textPrimary }}>
            Distribución por Algoritmo
          </h3>
          <div className="file-stats-algorithms-list">
            {Object.entries(algorithmCounts).map(([algorithm, count]) => (
              <div key={algorithm} className="file-stats-algorithm-item">
                <div className="file-stats-algorithm-info">
                  <span 
                    className="file-stats-algorithm-name"
                    style={{ color: colors.textPrimary }}
                  >
                    {algorithm}
                  </span>
                  <span 
                    className="file-stats-algorithm-count"
                    style={{ color: colors.textSecondary }}
                  >
                    {count} archivo{count !== 1 ? 's' : ''}
                  </span>
                </div>
                <div 
                  className="file-stats-algorithm-bar"
                  style={{ backgroundColor: colors.background }}
                >
                  <div 
                    className="file-stats-algorithm-fill"
                    style={{ 
                      backgroundColor: colors.primary,
                      width: `${(count / totalFiles) * 100}%`
                    }}
                  />
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};