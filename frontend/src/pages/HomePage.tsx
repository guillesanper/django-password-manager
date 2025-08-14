// HomePage.tsx - Con sistema de temas pero manteniendo la estructura original
import React from 'react';
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
  Database
} from 'lucide-react';
// CAMBIO: Usar useUnifiedTheme en lugar de useTheme
import { useUnifiedTheme } from '../theme/UnifiedThemeProvider';

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
  const { colors } = useUnifiedTheme(); // CAMBIO: useUnifiedTheme
  
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
const ActivityItem: React.FC<ActivityItemProps> = ({ icon: Icon, title, description, time, type }) => {
  const { colors } = useUnifiedTheme(); // CAMBIO: useUnifiedTheme
  
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
  const { colors } = useUnifiedTheme(); // CAMBIO: useUnifiedTheme
  
  return (
    <button
      onClick={onClick}
      className="rounded-lg shadow-md p-6 hover:shadow-lg transition-all hover:scale-105 text-left w-full"
      style={{ backgroundColor: colors.surface }}
    >
      <div className="flex items-center justify-between mb-4">
        <div className={`p-3 rounded-full ${color}`}>
          <Icon className="w-6 h-6 text-white" />
        </div>
      </div>
      <h3 className="text-lg font-semibold mb-2" style={{ color: colors.textPrimary }}>{title}</h3>
      <p className="text-sm" style={{ color: colors.textSecondary }}>{description}</p>
    </button>
  );
};

// Componente Principal del Home
export const HomePage: React.FC<HomePageProps> = ({ setCurrentPage }) => {
  const { colors } = useUnifiedTheme(); // CAMBIO: useUnifiedTheme
  
  const stats: StatCardProps[] = [
    {
      title: "Contraseñas Guardadas",
      value: "24",
      icon: Key,
      color: "bg-blue-500",
      trend: 12
    },
    {
      title: "Archivos Encriptados",
      value: "8",
      icon: FileText,
      color: "bg-green-500",
      trend: 25
    },
    {
      title: "Sesiones Activas",
      value: "3",
      icon: Users,
      color: "bg-purple-500"
    },
    {
      title: "Seguridad",
      value: "95%",
      icon: Shield,
      color: "bg-orange-500",
      trend: 5
    }
  ];

  const recentActivities: ActivityItemProps[] = [
    {
      icon: CheckCircle,
      title: "Contraseña actualizada",
      description: "Gmail - Contraseña actualizada exitosamente",
      time: "Hace 2 horas",
      type: "success"
    },
    {
      icon: Lock,
      title: "Archivo encriptado",
      description: "documento_importante.pdf fue encriptado",
      time: "Hace 4 horas",
      type: "info"
    },
    {
      icon: AlertCircle,
      title: "Contraseña débil detectada",
      description: "Se recomienda actualizar la contraseña de Facebook",
      time: "Hace 1 día",
      type: "warning"
    },
    {
      icon: Key,
      title: "Nueva contraseña generada",
      description: "Contraseña segura generada para LinkedIn",
      time: "Hace 2 días",
      type: "success"
    }
  ];

  const quickActions: QuickActionCardProps[] = [
    {
      title: "Generar Contraseña",
      description: "Crea contraseñas seguras y únicas",
      icon: Zap,
      color: "bg-yellow-500",
      onClick: () => setCurrentPage('generator')
    },
    {
      title: "Ver Contraseñas",
      description: "Accede a todas tus contraseñas guardadas",
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

  return (
    <div className="p-6 space-y-6" style={{ backgroundColor: colors.background, minHeight: '100vh' }}>
      {/* Header */}
      <div className="mb-8">
        <h1 className="text-3xl font-bold mb-2" style={{ color: colors.textPrimary }}>
          ¡Bienvenido de vuelta! 👋
        </h1>
        <p style={{ color: colors.textSecondary }}>
          Aquí tienes un resumen de tu actividad de seguridad
        </p>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
        {stats.map((stat, index) => (
          <StatCard key={index} {...stat} />
        ))}
      </div>

      {/* Main Content Grid */}
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
              {recentActivities.map((activity, index) => (
                <div key={index} style={{ borderTop: index > 0 ? `1px solid ${colors.border}` : undefined }}>
                  <ActivityItem {...activity} />
                </div>
              ))}
            </div>
            <div className="p-4" style={{ backgroundColor: colors.backgroundSecondary }}>
              <button className="text-sm font-medium" style={{ color: colors.primary }}>
                Ver toda la actividad →
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Quick Stats Bar */}
      <div className="rounded-lg shadow-md p-6" style={{ backgroundColor: colors.surface }}>
        <h3 className="text-lg font-semibold mb-4" style={{ color: colors.textPrimary }}>Resumen de Seguridad</h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <div className="text-center">
            <div className="flex items-center justify-center mb-2">
              <div className="w-12 h-12 bg-green-100 rounded-full flex items-center justify-center">
                <CheckCircle className="w-6 h-6 text-green-600" />
              </div>
            </div>
            <p className="text-2xl font-bold text-green-600">18</p>
            <p className="text-sm" style={{ color: colors.textSecondary }}>Contraseñas Seguras</p>
          </div>
          <div className="text-center">
            <div className="flex items-center justify-center mb-2">
              <div className="w-12 h-12 bg-yellow-100 rounded-full flex items-center justify-center">
                <AlertCircle className="w-6 h-6 text-yellow-600" />
              </div>
            </div>
            <p className="text-2xl font-bold text-yellow-600">4</p>
            <p className="text-sm" style={{ color: colors.textSecondary }}>Necesitan Actualización</p>
          </div>
          <div className="text-center">
            <div className="flex items-center justify-center mb-2">
              <div className="w-12 h-12 bg-red-100 rounded-full flex items-center justify-center">
                <Clock className="w-6 h-6 text-red-600" />
              </div>
            </div>
            <p className="text-2xl font-bold text-red-600">2</p>
            <p className="text-sm" style={{ color: colors.textSecondary }}>Contraseñas Antiguas</p>
          </div>
        </div>
      </div>
    </div>
  );
};