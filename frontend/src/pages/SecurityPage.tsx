import React, { useState, useEffect } from 'react';
import { 
  Shield, 
  AlertTriangle, 
  CheckCircle, 
  Eye, 
  EyeOff,
  RefreshCw,
  TrendingUp,
  TrendingDown,
  Clock,
  Key,
  Lock,
  AlertCircle,
  Info,
  ChevronRight,
  Filter,
  Search
} from 'lucide-react';
import { useUnifiedTheme } from '../components/UnifiedThemeProvider';
import { 
  securityService, 
  type SecurityAnalysisResponse, 
  type PasswordAnalysis,
  type SecurityIssue,
  type SecurityRecommendation
} from '../services/securityService';

// Componente de tarjeta de estadísticas rápidas
interface QuickStatCardProps {
  title: string;
  value: number | string;
  icon: React.ComponentType<{ className?: string }>;
  color: string;
  trend?: 'up' | 'down' | 'neutral';
  subtitle?: string;
}

const QuickStatCard: React.FC<QuickStatCardProps> = ({ 
  title, 
  value, 
  icon: Icon, 
  color, 
  trend,
  subtitle 
}) => {
  const { colors } = useUnifiedTheme();
  
  const getTrendIcon = () => {
    if (trend === 'up') return <TrendingUp className="w-4 h-4" style={{ color: colors.success }} />;
    if (trend === 'down') return <TrendingDown className="w-4 h-4" style={{ color: colors.error }} />;
    return null;
  };

  return (
    <div 
      className="rounded-lg shadow-md p-6 hover:shadow-lg transition-shadow"
      style={{ backgroundColor: colors.surface }}
    >
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm font-medium" style={{ color: colors.textSecondary }}>{title}</p>
          <p className="text-3xl font-bold mt-2" style={{ color: colors.textPrimary }}>{value}</p>
          {subtitle && (
            <div className="flex items-center mt-1 space-x-1">
              {getTrendIcon()}
              <p className="text-sm" style={{ color: colors.textMuted }}>{subtitle}</p>
            </div>
          )}
        </div>
        <div className={`p-3 rounded-full`} style={{ backgroundColor: color }}>
          <Icon className="w-6 h-6 text-white" />
        </div>
      </div>
    </div>
  );
};

// Componente de barra de progreso de fortaleza
interface StrengthProgressBarProps {
  strength: PasswordAnalysis['strength'];
  entropy: number;
  className?: string;
}

const StrengthProgressBar: React.FC<StrengthProgressBarProps> = ({ 
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

// Componente de tarjeta de contraseña individual
interface PasswordCardProps {
  password: PasswordAnalysis;
  onCheckBreach: (passwordId: number) => void;
  onViewPassword: (passwordId: number) => void;
  isBreachChecking: boolean;
}

const PasswordCard: React.FC<PasswordCardProps> = ({ 
  password, 
  onCheckBreach, 
  onViewPassword,
  isBreachChecking 
}) => {
  const { colors } = useUnifiedTheme();
  const [showDetails, setShowDetails] = useState(false);

  const getAgeColor = (days: number) => {
    if (days > 730) return colors.error;
    if (days > 365) return colors.warning;
    if (days > 180) return colors.info;
    return colors.success;
  };

  const formatAge = (days: number) => {
    if (days > 365) {
      const years = Math.floor(days / 365);
      return `${years} año${years > 1 ? 's' : ''}`;
    } else if (days > 30) {
      const months = Math.floor(days / 30);
      return `${months} mes${months > 1 ? 'es' : ''}`;
    } else {
      return `${days} día${days > 1 ? 's' : ''}`;
    }
  };

  return (
    <div 
      className="rounded-lg shadow-md p-6 hover:shadow-lg transition-all"
      style={{ backgroundColor: colors.surface }}
    >
      {/* Header con información básica */}
      <div className="flex items-start justify-between mb-4">
        <div className="flex-1">
          <div className="flex items-center space-x-2">
            <h3 className="font-semibold" style={{ color: colors.textPrimary }}>
              {password.website}
            </h3>
            {password.breach_info.is_breached && (
              <AlertTriangle className="w-4 h-4" style={{ color: colors.error }} />
            )}
          </div>
          <p className="text-sm" style={{ color: colors.textSecondary }}>
            {password.username}
          </p>
          <p className="text-xs mt-1" style={{ color: getAgeColor(password.age_days) }}>
            Creada hace {formatAge(password.age_days)}
          </p>
        </div>
        
        <button
          onClick={() => setShowDetails(!showDetails)}
          className="p-2 rounded-lg hover:bg-opacity-10 transition-colors"
          style={{ backgroundColor: showDetails ? colors.primary + '20' : 'transparent' }}
        >
          <ChevronRight 
            className={`w-4 h-4 transition-transform ${showDetails ? 'rotate-90' : ''}`}
            style={{ color: colors.textMuted }}
          />
        </button>
      </div>

      {/* Barra de fortaleza */}
      <StrengthProgressBar 
        strength={password.strength} 
        entropy={password.entropy} 
        className="mb-4"
      />

      {/* Información de breach */}
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center space-x-2">
          {password.breach_info.is_breached ? (
            <AlertTriangle className="w-4 h-4" style={{ color: colors.error }} />
          ) : (
            <CheckCircle className="w-4 h-4" style={{ color: colors.success }} />
          )}
          <span className="text-sm" style={{ color: colors.textSecondary }}>
            {password.breach_info.message}
          </span>
        </div>
        
        {password.breach_info.is_breached && (
          <span 
            className="text-xs px-2 py-1 rounded-full"
            style={{ 
              backgroundColor: colors.error + '20',
              color: colors.error
            }}
          >
            {securityService.formatBreachCount(password.breach_info.breach_count)} veces
          </span>
        )}
      </div>

      {/* Detalles expandibles */}
      {showDetails && (
        <div className="pt-4 border-t space-y-3" style={{ borderColor: colors.border }}>
          <div className="grid grid-cols-2 gap-4 text-sm">
            <div>
              <span style={{ color: colors.textSecondary }}>Entropía:</span>
              <span className="ml-2 font-medium" style={{ color: colors.textPrimary }}>
                {password.entropy.toFixed(1)} bits
              </span>
            </div>
            <div>
              <span style={{ color: colors.textSecondary }}>Puntuación:</span>
              <span className="ml-2 font-medium" style={{ color: password.strength.color }}>
                {password.strength.score}/100
              </span>
            </div>
            <div>
              <span style={{ color: colors.textSecondary }}>Última actualización:</span>
              <span className="ml-2" style={{ color: colors.textPrimary }}>
                {formatAge(password.last_updated_days)}
              </span>
            </div>
          </div>

          <div className="flex space-x-2 pt-2">
            <button
              onClick={() => onViewPassword(password.id)}
              className="flex-1 px-3 py-2 rounded-lg text-sm font-medium transition-colors"
              style={{ 
                backgroundColor: colors.primary,
                color: 'white'
              }}
            >
              <Eye className="w-4 h-4 inline mr-1" />
              Ver contraseña
            </button>
            <button
              onClick={() => onCheckBreach(password.id)}
              disabled={isBreachChecking}
              className="flex-1 px-3 py-2 rounded-lg text-sm font-medium transition-colors"
              style={{ 
                backgroundColor: colors.secondary,
                color: colors.secondaryText,
                opacity: isBreachChecking ? 0.5 : 1
              }}
            >
              {isBreachChecking ? (
                <RefreshCw className="w-4 h-4 inline mr-1 animate-spin" />
              ) : (
                <Shield className="w-4 h-4 inline mr-1" />
              )}
              Verificar breach
            </button>
          </div>
        </div>
      )}
    </div>
  );
};

// Componente de issue de seguridad
interface SecurityIssueCardProps {
  issue: SecurityIssue;
}

const SecurityIssueCard: React.FC<SecurityIssueCardProps> = ({ issue }) => {
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

// Componente principal
export const SecurityPage: React.FC = () => {
  const { colors } = useUnifiedTheme();
  
  // Estados
  const [analysisData, setAnalysisData] = useState<SecurityAnalysisResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState(false);
  
  // Filtros y búsqueda
  const [searchTerm, setSearchTerm] = useState('');
  const [strengthFilter, setStrengthFilter] = useState<string>('all');
  const [breachFilter, setBreachFilter] = useState<string>('all'); // CORREGIDO: Era setBreach Filter
  
  // Estados de modales y acciones
  const [breachChecking, setBreachChecking] = useState<number | null>(null);

  // Cargar datos iniciales
  useEffect(() => {
    loadSecurityAnalysis();
  }, []);

  const loadSecurityAnalysis = async () => {
    try {
      setLoading(true);
      setError(null);
      
      const response = await securityService.getSecurityAnalysis();
      
      if (response.success) {
        setAnalysisData(response);
      } else {
        setError(response.error || 'Error al cargar el análisis de seguridad');
      }
    } catch (err) {
      setError('Error de conexión al cargar el análisis');
      console.error('Error loading security analysis:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleRefresh = async () => {
    setRefreshing(true);
    await loadSecurityAnalysis();
    setRefreshing(false);
  };

  const handleCheckBreach = async (passwordId: number) => {
    // Esta función requeriría un modal para la master password
    setBreachChecking(passwordId);
    // TODO: Implementar modal de master password
    setTimeout(() => setBreachChecking(null), 2000); // Simulación
  };

  const handleViewPassword = (passwordId: number) => {
    // TODO: Implementar modal para ver contraseña con master password
    console.log('View password:', passwordId);
  };

  // Filtrar contraseñas
  const filteredPasswords = analysisData?.passwords.filter(password => {
    const matchesSearch = password.website.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         password.username.toLowerCase().includes(searchTerm.toLowerCase());
    
    const matchesStrength = strengthFilter === 'all' || password.strength.level === strengthFilter;
    
    const matchesBreach = breachFilter === 'all' || 
                         (breachFilter === 'breached' && password.breach_info.is_breached) ||
                         (breachFilter === 'safe' && !password.breach_info.is_breached);

    return matchesSearch && matchesStrength && matchesBreach;
  }) || [];

  // Loading state
  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center" style={{ backgroundColor: colors.background }}>
        <div className="text-center">
          <RefreshCw className="w-8 h-8 animate-spin mx-auto mb-4" style={{ color: colors.primary }} />
          <p style={{ color: colors.textSecondary }}>Analizando seguridad de contraseñas...</p>
        </div>
      </div>
    );
  }

  // Error state
  if (error) {
    return (
      <div className="min-h-screen flex items-center justify-center" style={{ backgroundColor: colors.background }}>
        <div className="text-center max-w-md">
          <AlertCircle className="w-12 h-12 mx-auto mb-4" style={{ color: colors.error }} />
          <h3 className="text-lg font-semibold mb-2" style={{ color: colors.textPrimary }}>
            Error al cargar el análisis
          </h3>
          <p className="mb-4" style={{ color: colors.textSecondary }}>
            {error}
          </p>
          <button
            onClick={loadSecurityAnalysis}
            className="px-4 py-2 rounded-lg text-white font-medium"
            style={{ backgroundColor: colors.primary }}
          >
            Reintentar
          </button>
        </div>
      </div>
    );
  }

  if (!analysisData || analysisData.total_passwords === 0) {
    return (
      <div className="min-h-screen p-6" style={{ backgroundColor: colors.background }}>
        <div className="max-w-4xl mx-auto text-center py-12">
          <Shield className="w-16 h-16 mx-auto mb-6" style={{ color: colors.textMuted }} />
          <h1 className="text-2xl font-bold mb-4" style={{ color: colors.textPrimary }}>
            Análisis de Seguridad
          </h1>
          <p style={{ color: colors.textSecondary }} className="mb-6">
            No tienes contraseñas guardadas para analizar. Agrega algunas contraseñas para obtener un análisis completo de seguridad.
          </p>
        </div>
      </div>
    );
  }

  const { analysis, passwords } = analysisData;
  const quickStats = securityService.calculateQuickStats(passwords);
  const securityGrade = securityService.calculateOverallSecurityGrade(analysis.overall_score);

  return (
    <div className="min-h-screen p-6" style={{ backgroundColor: colors.background }}>
      <div className="max-w-7xl mx-auto space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold mb-2" style={{ color: colors.textPrimary }}>
              Vigilancia de Seguridad
            </h1>
            <p style={{ color: colors.textSecondary }}>
              Monitorea y mejora la seguridad de tus contraseñas
            </p>
          </div>
          <button
            onClick={handleRefresh}
            disabled={refreshing}
            className="flex items-center space-x-2 px-4 py-2 rounded-lg text-white font-medium"
            style={{ backgroundColor: colors.primary }}
          >
            <RefreshCw className={`w-4 h-4 ${refreshing ? 'animate-spin' : ''}`} />
            <span>Actualizar</span>
          </button>
        </div>

        {/* Puntuación general */}
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
              style={{ color: securityGrade.color }}
            >
              {securityGrade.grade}
            </div>
            <div className="text-left">
              <div className="text-3xl font-bold" style={{ color: colors.textPrimary }}>
                {analysis.overall_score}/100
              </div>
              <div style={{ color: securityGrade.color }}>
                {securityGrade.description}
              </div>
            </div>
          </div>
        </div>

        {/* Estadísticas rápidas */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          <QuickStatCard
            title="Problemas Críticos"
            value={quickStats.criticalIssues}
            icon={AlertTriangle}
            color={colors.error}
            trend={quickStats.criticalIssues > 0 ? 'up' : 'neutral'}
            subtitle={quickStats.criticalIssues > 0 ? 'Requiere atención' : 'Todo bien'}
          />
          <QuickStatCard
            title="Fortaleza Promedio"
            value={`${quickStats.averageStrength}%`}
            icon={Shield}
            color={colors.primary}
            trend="up"
          />
          <QuickStatCard
            title="Contraseñas Comprometidas"
            value={quickStats.breachedPasswords}
            icon={AlertCircle}
            color={colors.warning}
            trend={quickStats.breachedPasswords > 0 ? 'up' : 'neutral'}
          />
          <QuickStatCard
            title="Contraseñas Fuertes"
            value={`${quickStats.strongPasswords}/${analysisData.total_passwords}`}
            icon={CheckCircle}
            color={colors.success}
            trend="up"
          />
        </div>

        {/* Problemas de seguridad */}
        {analysis.security_issues.length > 0 && (
          <div>
            <h2 className="text-xl font-semibold mb-4" style={{ color: colors.textPrimary }}>
              Problemas de Seguridad Detectados
            </h2>
            <div className="space-y-3">
              {analysis.security_issues.map((issue, index) => (
                <SecurityIssueCard key={index} issue={issue} />
              ))}
            </div>
          </div>
        )}

        {/* Recomendaciones */}
        {analysis.recommendations.length > 0 && (
          <div 
            className="rounded-lg p-6"
            style={{ backgroundColor: colors.surface }}
          >
            <h2 className="text-xl font-semibold mb-4" style={{ color: colors.textPrimary }}>
              Recomendaciones
            </h2>
            <ul className="space-y-2">
              {analysis.recommendations.map((recommendation, index) => (
                <li key={index} className="flex items-start space-x-2">
                  <CheckCircle className="w-5 h-5 mt-0.5 flex-shrink-0" style={{ color: colors.success }} />
                  <span style={{ color: colors.textSecondary }}>{recommendation}</span>
                </li>
              ))}
            </ul>
          </div>
        )}

        {/* Filtros */}
        <div 
          className="rounded-lg p-4"
          style={{ backgroundColor: colors.surface }}
        >
          <div className="flex flex-wrap items-center justify-between gap-4">
            <div className="flex items-center space-x-2">
              <Search className="w-5 h-5" style={{ color: colors.textMuted }} />
              <input
                type="text"
                placeholder="Buscar contraseñas..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="px-3 py-2 rounded-lg border"
                style={{
                  backgroundColor: colors.background,
                  borderColor: colors.border,
                  color: colors.textPrimary
                }}
              />
            </div>
            
            <div className="flex items-center space-x-4">
              <div className="flex items-center space-x-2">
                <Filter className="w-4 h-4" style={{ color: colors.textMuted }} />
                <select
                  value={strengthFilter}
                  onChange={(e) => setStrengthFilter(e.target.value)}
                  className="px-3 py-2 rounded-lg border"
                  style={{
                    backgroundColor: colors.background,
                    borderColor: colors.border,
                    color: colors.textPrimary
                  }}
                >
                  <option value="all">Todas las fortalezas</option>
                  <option value="very_strong">Muy fuertes</option>
                  <option value="strong">Fuertes</option>
                  <option value="moderate">Moderadas</option>
                  <option value="weak">Débiles</option>
                  <option value="very_weak">Muy débiles</option>
                </select>
              </div>

              <select
                value={breachFilter}
                onChange={(e) => setBreachFilter(e.target.value)}
                className="px-3 py-2 rounded-lg border"
                style={{
                  backgroundColor: colors.background,
                  borderColor: colors.border,
                  color: colors.textPrimary
                }}
              >
                <option value="all">Todas</option>
                <option value="breached">Comprometidas</option>
                <option value="safe">Seguras</option>
              </select>
            </div>
          </div>
        </div>

        {/* Lista de contraseñas */}
        <div>
          <h2 className="text-xl font-semibold mb-4" style={{ color: colors.textPrimary }}>
            Análisis Detallado ({filteredPasswords.length} contraseñas)
          </h2>
          
          {filteredPasswords.length > 0 ? (
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {filteredPasswords.map((password) => (
                <PasswordCard
                  key={password.id}
                  password={password}
                  onCheckBreach={handleCheckBreach}
                  onViewPassword={handleViewPassword}
                  isBreachChecking={breachChecking === password.id}
                />
              ))}
            </div>
          ) : (
            <div className="text-center py-12">
              <Search className="w-12 h-12 mx-auto mb-4" style={{ color: colors.textMuted }} />
              <p style={{ color: colors.textSecondary }}>
                No se encontraron contraseñas que coincidan con los filtros aplicados
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};