import React, { useState, useEffect } from 'react';
import { 
  Shield, 
  AlertTriangle, 
  CheckCircle, 
  RefreshCw,
  AlertCircle,
  Search
} from 'lucide-react';
import { useUnifiedTheme } from '../components/UnifiedThemeProvider';
import { 
  securityService, 
  type SecurityAnalysisResponse
} from '../services/securityService';

import { 
  LogOut,
  Activity,
  Info,
  MapPin,
  Monitor
} from 'lucide-react';
import { sessionService, type SessionStatistics, type SecurityReport } from '../services/sessionService';
import { SessionCard } from '../components/security/SessionCard';

import { QuickStatCard } from '../components/security/QuickStatCard';
import { PasswordCard } from '../components/security/PasswordCard';
import { SecurityIssueCard } from '../components/security/SecurityIssueCard';
import { SecurityFilters } from '../components/security/SecurityFilters';
import { SecurityHeader } from '../components/security/SecurityHeader';
import { SecurityScoreCard } from '../components/security/SecurityScoreCard';
import { SecurityRecommendations } from '../components/security/SecurityRecommendations';
import '../styles/security.css';

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
  const [breachFilter, setBreachFilter] = useState<string>('all');

  // Estados para gestión de sesiones
const [sessionsData, setSessionsData] = useState<SessionStatistics | null>(null);
const [securityReport, setSecurityReport] = useState<SecurityReport | null>(null);
const [loadingSessions, setLoadingSessions] = useState(false);
const [terminatingSession, setTerminatingSession] = useState<string | null>(null);
const [terminatingAll, setTerminatingAll] = useState(false);
  
  // Estados de modales y acciones
  const [breachChecking, setBreachChecking] = useState<number | null>(null);

  // Cargar datos iniciales
  useEffect(() => {
    loadSecurityAnalysis();
    loadSessionsData();
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

  const loadSessionsData = async () => {
    try {
      setLoadingSessions(true);
      
      const [sessionsResponse, reportResponse] = await Promise.all([
        sessionService.getUserSessions(),
        sessionService.getSecurityReport()
      ]);
      
      if (sessionsResponse.success && sessionsResponse.data) {
        setSessionsData(sessionsResponse.data);
      }
      
      if (reportResponse.success && reportResponse.data) {
        setSecurityReport(reportResponse.data);
      }
    } catch (err) {
      console.error('Error loading sessions:', err);
    } finally {
      setLoadingSessions(false);
    }
  };

  const handleRefresh = async () => {
    setRefreshing(true);
    await loadSecurityAnalysis();
    setRefreshing(false);
  };

  const handleCheckBreach = async (passwordId: number) => {
    setBreachChecking(passwordId);
    setTimeout(() => setBreachChecking(null), 2000);
  };

  const handleViewPassword = (passwordId: number) => {
    console.log('View password:', passwordId);
  };

  const handleTerminateSession = async (sessionId: string) => {
    if (!confirm('¿Estás seguro de que quieres cerrar esta sesión?')) return;
    
    setTerminatingSession(sessionId);
    const result = await sessionService.terminateSession(sessionId, 'user_manual_termination');
    
    if (result.success) {
      await loadSessionsData();
    } else {
      alert(result.error || 'Error al cerrar sesión');
    }
    
    setTerminatingSession(null);
  };

  const handleTerminateAllOtherSessions = async () => {
    if (!confirm('¿Estás seguro de que quieres cerrar todas las demás sesiones? Esta acción no se puede deshacer.')) return;
    
    setTerminatingAll(true);
    const result = await sessionService.terminateAllOtherSessions('security_cleanup');
    
    if (result.success) {
      alert(`Se cerraron ${result.data?.terminated_count || 0} sesiones correctamente`);
      await loadSessionsData();
    } else {
      alert(result.error || 'Error al cerrar sesiones');
    }
    setTerminatingAll(false);
  };

  const handleFlagSession = async (sessionId: string) => {
    if (!confirm('¿Marcar esta sesión como sospechosa? Se registrará como evento de seguridad.')) return;
    
    const result = await sessionService.flagSessionSuspicious(sessionId, 'user_flagged_suspicious');
    
    if (result.success) {
      alert('Sesión marcada como sospechosa correctamente');
      await loadSessionsData();
    } else {
      alert(result.error || 'Error al marcar sesión');
    }
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
        <SecurityHeader onRefresh={handleRefresh} refreshing={refreshing} />

        {/* Puntuación general */}
        <SecurityScoreCard
          score={analysis.overall_score}
          grade={securityGrade.grade}
          description={securityGrade.description}
          gradeColor={securityGrade.color}
        />

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
        <SecurityRecommendations recommendations={analysis.recommendations} />

        {/* Filtros */}
        <SecurityFilters
          searchTerm={searchTerm}
          onSearchChange={setSearchTerm}
          strengthFilter={strengthFilter}
          onStrengthFilterChange={setStrengthFilter}
          breachFilter={breachFilter}
          onBreachFilterChange={setBreachFilter}
        />

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

        {/* Gestión de sesiones */}
        {/* Sección de Gestión de Sesiones */}
{sessionsData && sessionsData.total_sessions > 0 && (
  <div className="space-y-6 mt-12">
    <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
      <div>
        <h2 className="text-2xl font-bold" style={{ color: colors.textPrimary }}>
          Sesiones Activas
        </h2>
        <p style={{ color: colors.textSecondary }}>
          Monitorea y administra tus dispositivos conectados
        </p>
      </div>
      {sessionsData.total_sessions > 1 && (
        <button
          onClick={handleTerminateAllOtherSessions}
          disabled={terminatingAll}
          className="security-session-button security-session-button-danger"
          style={{ maxWidth: '300px' }}
        >
          {terminatingAll ? (
            <RefreshCw className="security-session-button-icon security-session-button-spinner" />
          ) : (
            <LogOut className="security-session-button-icon" />
          )}
          <span>Cerrar todas las demás</span>
        </button>
      )}
    </div>

    {/* Métricas de sesiones */}
    <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
      <div
        className="rounded-lg p-6"
        style={{ backgroundColor: colors.surface }}
      >
        <div className="flex items-center justify-between">
          <div>
            <p className="text-sm font-medium" style={{ color: colors.textSecondary }}>
              Dispositivos Únicos
            </p>
            <p className="text-3xl font-bold mt-2" style={{ color: colors.textPrimary }}>
              {sessionsData.unique_devices}
            </p>
          </div>
          <Monitor className="w-8 h-8" style={{ color: colors.primary }} />
        </div>
      </div>

      <div
        className="rounded-lg p-6"
        style={{ backgroundColor: colors.surface }}
      >
        <div className="flex items-center justify-between">
          <div>
            <p className="text-sm font-medium" style={{ color: colors.textSecondary }}>
              Ubicaciones
            </p>
            <p className="text-3xl font-bold mt-2" style={{ color: colors.textPrimary }}>
              {sessionsData.unique_locations}
            </p>
          </div>
          <MapPin className="w-8 h-8" style={{ color: colors.primary }} />
        </div>
      </div>

      <div
        className="rounded-lg p-6"
        style={{ backgroundColor: colors.surface }}
      >
        <div className="flex items-center justify-between">
          <div>
            <p className="text-sm font-medium" style={{ color: colors.textSecondary }}>
              Estado de Seguridad
            </p>
            <p className="text-lg font-bold mt-2" style={{ 
              color: sessionsData.security_summary.status === 'good' ? colors.success :
                     sessionsData.security_summary.status === 'warning' ? colors.warning :
                     sessionsData.security_summary.status === 'critical' ? colors.error :
                     colors.textPrimary
            }}>
              {sessionsData.security_summary.status === 'good' ? 'Todo bien' :
               sessionsData.security_summary.status === 'warning' ? 'Advertencia' :
               sessionsData.security_summary.status === 'critical' ? 'Crítico' :
               'Sin sesiones'}
            </p>
          </div>
          <Activity className="w-8 h-8" style={{ 
            color: sessionsData.security_summary.status === 'good' ? colors.success :
                   sessionsData.security_summary.status === 'warning' ? colors.warning :
                   colors.error
          }} />
        </div>
      </div>
    </div>

    {/* Alertas de seguridad del reporte */}
    {securityReport && securityReport.recommendations.length > 0 && (
      <div
        className="rounded-lg p-6"
        style={{ backgroundColor: colors.surface }}
      >
        <h3 className="text-lg font-semibold mb-4" style={{ color: colors.textPrimary }}>
          Recomendaciones de Seguridad
        </h3>
        <div className="space-y-3">
          {securityReport.recommendations.map((rec, idx) => (
            <div
              key={idx}
              className="flex items-start space-x-3 p-3 rounded-lg"
              style={{
                backgroundColor: sessionService.getSeverityColor(rec.priority) + '10',
                borderLeft: `4px solid ${sessionService.getSeverityColor(rec.priority)}`
              }}
            >
              <Info className="w-5 h-5 mt-0.5 flex-shrink-0" style={{ 
                color: sessionService.getSeverityColor(rec.priority) 
              }} />
              <div className="flex-1">
                <p className="font-medium" style={{ color: colors.textPrimary }}>
                  {rec.message}
                </p>
                <span
                  className="text-xs px-2 py-1 rounded-full inline-block mt-1"
                  style={{
                    backgroundColor: sessionService.getSeverityColor(rec.priority) + '20',
                    color: sessionService.getSeverityColor(rec.priority)
                  }}
                >
                  Prioridad: {rec.priority}
                </span>
              </div>
            </div>
          ))}
        </div>
      </div>
    )}

    {/* Lista de sesiones */}
    {loadingSessions ? (
      <div className="text-center py-12">
        <RefreshCw className="w-8 h-8 animate-spin mx-auto mb-4" style={{ color: colors.primary }} />
        <p style={{ color: colors.textSecondary }}>Cargando sesiones...</p>
      </div>
    ) : (
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {sessionsData.sessions.map((session) => (
          <SessionCard
            key={session.session_id}
            session={session}
            onTerminate={handleTerminateSession}
            onFlag={handleFlagSession}
            isTerminating={terminatingSession === session.session_id}
          />
        ))}
      </div>
    )}
  </div>
)}
      </div>
    </div>
  );
};