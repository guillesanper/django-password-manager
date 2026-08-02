// HomePage.tsx - Con datos reales del backend
import React, { useState, useEffect } from 'react';
import { 
  Key, 
  Shield, 
  FileText, 
  Users, 
  Activity, 
  TrendingUp,
  Clock,
  AlertCircle,
  CheckCircle,
  Lock,
  Zap,
  Database,
  Loader
} from 'lucide-react';
import { useUnifiedTheme } from '../components/UnifiedThemeProvider';
import { dashboardService, type DashboardStats, type ActivityItem, type SecuritySummary } from '../services/dashboardService';

export interface HomePageProps {
  setCurrentPage: (page: string) => void;
}

interface StatCardProps {
  title: string;
  value: string;
  icon: React.ComponentType<{ className?: string }>;
  color: string;
  trend?: number;
}

interface ActivityItemProps {
  icon: React.ComponentType<{ className?: string }>;
  title: string;
  description: string;
  time: string;
  type: 'success' | 'warning' | 'error' | 'info';
}

interface QuickActionCardProps {
  title: string;
  description: string;
  icon: React.ComponentType<{ className?: string }>;
  color: string;
  onClick: () => void;
}

// Componente de Tarjeta de Estadística
const StatCard: React.FC<StatCardProps> = ({ title, value, icon: Icon, color, trend }) => {
  const { colors } = useUnifiedTheme();
  
  return (
    <div 
      className="rounded-lg shadow-md p-6 hover:shadow-lg transition-shadow"
      style={{ backgroundColor: colors.surface }}
    >
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm font-medium" style={{ color: colors.textSecondary }}>{title}</p>
          <p className="text-3xl font-bold" style={{ color: colors.textPrimary }}>{value}</p>
          {trend && (
            <p className="text-sm flex items-center mt-1" style={{ color: colors.success }}>
              <TrendingUp className="w-4 h-4 mr-1" />
              +{trend}% desde el mes pasado
            </p>
          )}
        </div>
        <div className={`p-3 rounded-full ${color}`}>
          <Icon className="w-6 h-6 text-white" />
        </div>
      </div>
    </div>
  );
};

// Componente de Actividad Reciente
const ActivityItemComponent: React.FC<ActivityItemProps> = ({ icon: Icon, title, description, time, type }) => {
  const { colors } = useUnifiedTheme();
  
  const getTypeColor = (type: string): string => {
    switch (type) {
      case 'success': return 'text-green-600 bg-green-100';
      case 'warning': return 'text-yellow-600 bg-yellow-100';
      case 'error': return 'text-red-600 bg-red-100';
      default: return 'text-blue-600 bg-blue-100';
    }
  };

  return (
    <div 
      className="flex items-start space-x-4 p-4 rounded-lg transition-colors"
      style={{ 
        backgroundColor: 'transparent'
      }}
      onMouseEnter={(e) => {
        e.currentTarget.style.backgroundColor = colors.surfaceHover;
      }}
      onMouseLeave={(e) => {
        e.currentTarget.style.backgroundColor = 'transparent';
      }}
    >
      <div className={`p-2 rounded-full ${getTypeColor(type)}`}>
        <Icon className="w-4 h-4" />
      </div>
      <div className="flex-1 min-w-0">
        <p className="text-sm font-medium" style={{ color: colors.textPrimary }}>{title}</p>
        <p className="text-sm" style={{ color: colors.textSecondary }}>{description}</p>
      </div>
      <div className="text-sm" style={{ color: colors.textMuted }}>
        {time}
      </div>
    </div>
  );
};

// Componente de Acceso Rápido
const QuickActionCard: React.FC<QuickActionCardProps> = ({ title, description, icon: Icon, color, onClick }) => {
  const { colors } = useUnifiedTheme();
  
  return (
    <button
      onClick={onClick}
      className="rounded-lg shadow-md p-6 hover:shadow-lg transition-all hover:scale-105 text-left w-full"
      style={{ backgroundColor: colors.surface, margin: '8px' }}
    >
      <div className="flex items-center justify-between mb-4">
        <div className={`p-3 rounded-full ${color}`} style={{ marginLeft: '4px', marginRight: '4px', marginTop: '2px' }}>
          <Icon className="w-6 h-6 text-white" />
        </div>
      </div>
      <h3 className="text-lg font-semibold mb-2" style={{ color: colors.textPrimary, marginLeft: '6px', marginRight: '6px', marginBottom: '8px' }}>{title}</h3>
      <p className="text-sm" style={{ color: colors.textSecondary, marginLeft: '6px', marginRight: '6px', marginBottom: '4px' }}>{description}</p>
    </button>
  );
};

// Componente Principal del Home
export const HomePage: React.FC<HomePageProps> = ({ setCurrentPage }) => {
  const { colors } = useUnifiedTheme();
  
  // Estados para datos reales
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [activities, setActivities] = useState<ActivityItem[]>([]);
  const [securitySummary, setSecuritySummary] = useState<SecuritySummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  
  useEffect(() => {
    const loadDashboardData = async () => {
      setLoading(true);
      setError(null);
      
      try {
        const [statsResponse, activitiesResponse, securityResponse] = await Promise.all([
          dashboardService.getDashboardStats(),
          dashboardService.getRecentActivity(),
          dashboardService.getSecuritySummary()
        ]);
        
        if (statsResponse.success && statsResponse.stats) {
          setStats(statsResponse.stats);
        } else {
          console.error('Error loading stats:', statsResponse.error);
        }
        
        if (activitiesResponse.success && activitiesResponse.activities) {
          setActivities(activitiesResponse.activities);
        } else {
          console.error('Error loading activities:', activitiesResponse.error);
        }
        
        if (securityResponse.success && securityResponse.summary) {
          setSecuritySummary(securityResponse.summary);
        } else {
          console.error('Error loading security summary:', securityResponse.error);
        }
        
      } catch (error) {
        console.error('Error loading dashboard:', error);
        setError('Error al cargar los datos del dashboard');
      } finally {
        setLoading(false);
      }
    };
    
    loadDashboardData();
  }, []);

  // Generar tarjetas de estadísticas con datos reales
  const statsCards: StatCardProps[] = stats ? [
    {
      title: "Contraseñas Guardadas",
      value: stats.passwords_count.toString(),
      icon: Key,
      color: "bg-blue-500",
      
    },
    {
      title: "Archivos Encriptados",
      value: stats.files_count.toString(),
      icon: FileText,
      color: "bg-green-500",
      
    },
    {
      title: "Sesiones Activas",
      value: stats.active_sessions.toString(),
      icon: Users,
      color: "bg-purple-500",
      
    },
    {
      title: "Seguridad",
      value: `${stats.security_score}%`,
      icon: Shield,
      color: "bg-orange-500",
      
    }
  ] : [];

  // Mapear actividades reales con iconos apropiados
  const getActivityIcon = (activityType: string) => {
    switch (activityType) {
      case 'password_created':
      case 'password_updated':
        return Key;
      case 'password_deleted':
        return AlertCircle;
      case 'file_uploaded':
      case 'file_encrypted':
        return Lock;
      case 'file_downloaded':
        return FileText;
      case 'login':
        return CheckCircle;
      default:
        return Activity;
    }
  };

  const mappedActivities: ActivityItemProps[] = activities.map(activity => ({
    icon: getActivityIcon(activity.type),
    title: activity.title,
    description: activity.description,
    time: activity.time,
    type: activity.activity_type
  }));

  const quickActions: QuickActionCardProps[] = [
    {
      title: "Generar Contraseña",
      description: "Almacena contraseñas de manera segura",
      icon: Zap,
      color: "bg-yellow-500",
      onClick: () => setCurrentPage('generator')
    },
    {
      title: "Ver Contraseñas",
      description: "Accede a tus contraseñas guardadas",
      icon: Database,
      color: "bg-blue-500",
      onClick: () => setCurrentPage('passwords')
    },
    {
      title: "Encriptar Archivos",
      description: "Protege tus documentos importantes",
      icon: Lock,
      color: "bg-green-500",
      onClick: () => setCurrentPage('files')
    }
  ];

  // Si hay error, mostrarlo
  if (error) {
    return (
      <div className="p-6 space-y-6" style={{ backgroundColor: colors.background, minHeight: '100vh' }}>
        <div className="flex items-center justify-center min-h-[400px]">
          <div 
            className="rounded-lg p-6 text-center"
            style={{ backgroundColor: colors.surface }}
          >
            <AlertCircle className="w-12 h-12 mx-auto mb-4" style={{ color: colors.error }} />
            <h3 className="text-lg font-semibold mb-2" style={{ color: colors.textPrimary }}>
              Error al cargar el dashboard
            </h3>
            <p style={{ color: colors.textSecondary }}>
              {error}
            </p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6" style={{ backgroundColor: colors.background, minHeight: '100vh' }}>
      {/* Header */}
      <div className="mb-8">
        <h1 className="text-3xl font-bold mb-2" style={{ color: colors.textPrimary }}>
          ¡Bienvenido de vuelta!
        </h1>
        <p style={{ color: colors.textSecondary }}>
          Aquí tienes un resumen de tu actividad de seguridad
        </p>
      </div>

      {/* Loading State */}
      {loading && (
        <div className="flex items-center justify-center min-h-[400px]">
          <div className="flex items-center space-x-2">
            <Loader className="w-6 h-6 animate-spin" style={{ color: colors.primary }} />
            <span style={{ color: colors.textSecondary }}>Cargando dashboard...</span>
          </div>
        </div>
      )}

      {/* Stats Grid */}
      {!loading && statsCards.length > 0 && (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
          {statsCards.map((stat, index) => (
            <StatCard key={index} {...stat} />
          ))}
        </div>
      )}

      {/* Main Content Grid */}
      {!loading && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Quick Actions */}
          <div className="lg:col-span-2">
            <h2 className="text-xl font-semibold mb-4" style={{ color: colors.textPrimary }}>Acciones Rápidas</h2>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-8">
              {quickActions.map((action, index) => (
                <QuickActionCard key={index} {...action} />
              ))}
            </div>

            {/* Security Tips */}
            <div 
              className="rounded-lg p-6 border" 
              style={{ 
                background: `linear-gradient(to right, ${colors.primary}10, ${colors.primary}05)`,
                borderColor: colors.border
              }}
            >
              <div className="flex items-center mb-4">
                <Shield className="w-6 h-6 mr-2" style={{ color: colors.primary }} />
                <h3 className="text-lg font-semibold" style={{ color: colors.textPrimary }}>Consejos de Seguridad</h3>
              </div>
              <ul className="space-y-2" style={{ color: colors.textSecondary }}>
                <li className="flex items-start">
                  <CheckCircle className="w-4 h-4 mr-2 mt-0.5" style={{ color: colors.success }} />
                  <span className="text-sm">Usa contraseñas únicas para cada cuenta</span>
                </li>
                <li className="flex items-start">
                  <CheckCircle className="w-4 h-4 mr-2 mt-0.5" style={{ color: colors.success }} />
                  <span className="text-sm">Revisa regularmente la seguridad de tus contraseñas</span>
                </li>
                <li className="flex items-start">
                  <CheckCircle className="w-4 h-4 mr-2 mt-0.5" style={{ color: colors.success }} />
                  <span className="text-sm">Mantén tus archivos importantes encriptados</span>
                </li>
              </ul>
            </div>
          </div>

          {/* Recent Activity */}
          <div className="lg:col-span-1">
            <div className="rounded-lg shadow-md" style={{ backgroundColor: colors.surface }}>
              <div className="p-6 border-b" style={{ borderColor: colors.border }}>
                <div className="flex items-center justify-between">
                  <h2 className="text-lg font-semibold" style={{ color: colors.textPrimary }}>Actividad Reciente</h2>
                  <Activity className="w-5 h-5" style={{ color: colors.textMuted }} />
                </div>
              </div>
              <div style={{ borderColor: colors.border }}>
                {mappedActivities.length > 0 ? (
                  mappedActivities.map((activity, index) => (
                    <div key={index} style={{ borderTop: index > 0 ? `1px solid ${colors.border}` : undefined }}>
                      <ActivityItemComponent {...activity} />
                    </div>
                  ))
                ) : (
                  <div className="p-6 text-center">
                    <p style={{ color: colors.textSecondary }}>No hay actividad reciente</p>
                  </div>
                )}
              </div>
              <div className="p-4" style={{ backgroundColor: colors.backgroundSecondary }}>
                <button className="text-sm font-medium" style={{ color: colors.primary }}>
                  Ver toda la actividad →
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Quick Stats Bar - Usando datos reales de seguridad */}
      {!loading && securitySummary && (
        <div className="rounded-lg shadow-md p-6" style={{ backgroundColor: colors.surface }}>
          <h3 className="text-lg font-semibold mb-4" style={{ color: colors.textPrimary }}>Resumen de Seguridad</h3>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div className="text-center">
              <div className="flex items-center justify-center mb-2">
                <div className="w-12 h-12 bg-green-100 rounded-full flex items-center justify-center">
                  <CheckCircle className="w-6 h-6 text-green-600" />
                </div>
              </div>
              <p className="text-2xl font-bold text-green-600">{securitySummary.strong_passwords}</p>
              <p className="text-sm" style={{ color: colors.textSecondary }}>Contraseñas Seguras</p>
            </div>
            <div className="text-center">
              <div className="flex items-center justify-center mb-2">
                <div className="w-12 h-12 bg-yellow-100 rounded-full flex items-center justify-center">
                  <AlertCircle className="w-6 h-6 text-yellow-600" />
                </div>
              </div>
              <p className="text-2xl font-bold text-yellow-600">{securitySummary.needs_update}</p>
              <p className="text-sm" style={{ color: colors.textSecondary }}>Necesitan Actualización</p>
            </div>
            <div className="text-center">
              <div className="flex items-center justify-center mb-2">
                <div className="w-12 h-12 bg-red-100 rounded-full flex items-center justify-center">
                  <Clock className="w-6 h-6 text-red-600" />
                </div>
              </div>
              <p className="text-2xl font-bold text-red-600">{securitySummary.old_passwords}</p>
              <p className="text-sm" style={{ color: colors.textSecondary }}>Contraseñas Antiguas</p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};