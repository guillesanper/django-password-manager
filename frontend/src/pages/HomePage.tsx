// HomePage.tsx - Corregido
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
  return (
    <div className="bg-white rounded-lg shadow-md p-6 hover:shadow-lg transition-shadow">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm font-medium text-gray-600">{title}</p>
          <p className="text-3xl font-bold text-gray-900">{value}</p>
          {trend && (
            <p className="text-sm text-green-600 flex items-center mt-1">
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
  const getTypeColor = (type: string): string => {
    switch (type) {
      case 'success': return 'text-green-600 bg-green-100';
      case 'warning': return 'text-yellow-600 bg-yellow-100';
      case 'error': return 'text-red-600 bg-red-100';
      default: return 'text-blue-600 bg-blue-100';
    }
  };

  return (
    <div className="flex items-start space-x-4 p-4 hover:bg-gray-50 rounded-lg transition-colors">
      <div className={`p-2 rounded-full ${getTypeColor(type)}`}>
        <Icon className="w-4 h-4" />
      </div>
      <div className="flex-1 min-w-0">
        <p className="text-sm font-medium text-gray-900">{title}</p>
        <p className="text-sm text-gray-500">{description}</p>
      </div>
      <div className="text-sm text-gray-400">
        {time}
      </div>
    </div>
  );
};

// Componente de Acceso Rápido
const QuickActionCard: React.FC<QuickActionCardProps> = ({ title, description, icon: Icon, color, onClick }) => {
  return (
    <button
      onClick={onClick}
      className="bg-white rounded-lg shadow-md p-6 hover:shadow-lg transition-all hover:scale-105 text-left w-full"
    >
      <div className="flex items-center justify-between mb-4">
        <div className={`p-3 rounded-full ${color}`}>
          <Icon className="w-6 h-6 text-white" />
        </div>
      </div>
      <h3 className="text-lg font-semibold text-gray-900 mb-2">{title}</h3>
      <p className="text-sm text-gray-600">{description}</p>
    </button>
  );
};

// Componente Principal del Home
export const HomePage: React.FC<HomePageProps> = ({ setCurrentPage }) => {
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
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-gray-900 mb-2">
          ¡Bienvenido de vuelta! 👋
        </h1>
        <p className="text-gray-600">
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
          <h2 className="text-xl font-semibold text-gray-900 mb-4">Acciones Rápidas</h2>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-8">
            {quickActions.map((action, index) => (
              <QuickActionCard key={index} {...action} />
            ))}
          </div>

          {/* Security Tips */}
          <div className="bg-gradient-to-r from-blue-50 to-indigo-50 rounded-lg p-6 border border-blue-200">
            <div className="flex items-center mb-4">
              <Shield className="w-6 h-6 text-blue-600 mr-2" />
              <h3 className="text-lg font-semibold text-blue-900">Consejos de Seguridad</h3>
            </div>
            <ul className="space-y-2 text-blue-800">
              <li className="flex items-start">
                <CheckCircle className="w-4 h-4 mr-2 mt-0.5 text-blue-600" />
                <span className="text-sm">Usa contraseñas únicas para cada cuenta</span>
              </li>
              <li className="flex items-start">
                <CheckCircle className="w-4 h-4 mr-2 mt-0.5 text-blue-600" />
                <span className="text-sm">Revisa regularmente la seguridad de tus contraseñas</span>
              </li>
              <li className="flex items-start">
                <CheckCircle className="w-4 h-4 mr-2 mt-0.5 text-blue-600" />
                <span className="text-sm">Mantén tus archivos importantes encriptados</span>
              </li>
            </ul>
          </div>
        </div>

        {/* Recent Activity */}
        <div className="lg:col-span-1">
          <div className="bg-white rounded-lg shadow-md">
            <div className="p-6 border-b border-gray-200">
              <div className="flex items-center justify-between">
                <h2 className="text-lg font-semibold text-gray-900">Actividad Reciente</h2>
                <Activity className="w-5 h-5 text-gray-400" />
              </div>
            </div>
            <div className="divide-y divide-gray-200">
              {recentActivities.map((activity, index) => (
                <ActivityItem key={index} {...activity} />
              ))}
            </div>
            <div className="p-4 bg-gray-50">
              <button className="text-sm text-blue-600 hover:text-blue-800 font-medium">
                Ver toda la actividad →
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Quick Stats Bar */}
      <div className="bg-white rounded-lg shadow-md p-6">
        <h3 className="text-lg font-semibold text-gray-900 mb-4">Resumen de Seguridad</h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <div className="text-center">
            <div className="flex items-center justify-center mb-2">
              <div className="w-12 h-12 bg-green-100 rounded-full flex items-center justify-center">
                <CheckCircle className="w-6 h-6 text-green-600" />
              </div>
            </div>
            <p className="text-2xl font-bold text-green-600">18</p>
            <p className="text-sm text-gray-600">Contraseñas Seguras</p>
          </div>
          <div className="text-center">
            <div className="flex items-center justify-center mb-2">
              <div className="w-12 h-12 bg-yellow-100 rounded-full flex items-center justify-center">
                <AlertCircle className="w-6 h-6 text-yellow-600" />
              </div>
            </div>
            <p className="text-2xl font-bold text-yellow-600">4</p>
            <p className="text-sm text-gray-600">Necesitan Actualización</p>
          </div>
          <div className="text-center">
            <div className="flex items-center justify-center mb-2">
              <div className="w-12 h-12 bg-red-100 rounded-full flex items-center justify-center">
                <Clock className="w-6 h-6 text-red-600" />
              </div>
            </div>
            <p className="text-2xl font-bold text-red-600">2</p>
            <p className="text-sm text-gray-600">Contraseñas Antiguas</p>
          </div>
        </div>
      </div>
    </div>
  );
};