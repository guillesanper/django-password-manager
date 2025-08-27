
import { useState, useEffect } from 'react';
import { dashboardService, type DashboardStats, type ActivityItem, type SecuritySummary } from '../../services/dashboardService';

interface DashboardState {
  stats: DashboardStats | null;
  activities: ActivityItem[];
  securitySummary: SecuritySummary | null;
  loading: boolean;
  error: string | null;
}

interface UseDashboardReturn extends DashboardState {
  refreshDashboard: () => Promise<void>;
  refreshStats: () => Promise<void>;
  refreshActivities: () => Promise<void>;
  refreshSecurity: () => Promise<void>;
}

export const useDashboard = (): UseDashboardReturn => {
  const [state, setState] = useState<DashboardState>({
    stats: null,
    activities: [],
    securitySummary: null,
    loading: true,
    error: null,
  });

  const loadStats = async () => {
    try {
      const response = await dashboardService.getDashboardStats();
      if (response.success && response.stats) {
        setState(prev => ({ ...prev, stats: response.stats!, error: null }));
      } else {
        setState(prev => ({ ...prev, error: response.error || 'Error al cargar estadísticas' }));
      }
    } catch (error) {
      setState(prev => ({ ...prev, error: 'Error al cargar estadísticas' }));
    }
  };

  const loadActivities = async () => {
    try {
      const response = await dashboardService.getRecentActivity();
      if (response.success && response.activities) {
        setState(prev => ({ ...prev, activities: response.activities!, error: null }));
      } else {
        setState(prev => ({ ...prev, error: response.error || 'Error al cargar actividades' }));
      }
    } catch (error) {
      setState(prev => ({ ...prev, error: 'Error al cargar actividades' }));
    }
  };

  const loadSecurity = async () => {
    try {
      const response = await dashboardService.getSecuritySummary();
      if (response.success && response.summary) {
        setState(prev => ({ ...prev, securitySummary: response.summary!, error: null }));
      } else {
        setState(prev => ({ ...prev, error: response.error || 'Error al cargar resumen de seguridad' }));
      }
    } catch (error) {
      setState(prev => ({ ...prev, error: 'Error al cargar resumen de seguridad' }));
    }
  };

  const loadDashboard = async () => {
    setState(prev => ({ ...prev, loading: true, error: null }));
    
    try {
      await Promise.all([
        loadStats(),
        loadActivities(),
        loadSecurity()
      ]);
    } catch (error) {
      setState(prev => ({ 
        ...prev, 
        error: 'Error al cargar los datos del dashboard' 
      }));
    } finally {
      setState(prev => ({ ...prev, loading: false }));
    }
  };

  const refreshDashboard = async () => {
    await loadDashboard();
  };

  const refreshStats = async () => {
    await loadStats();
  };

  const refreshActivities = async () => {
    await loadActivities();
  };

  const refreshSecurity = async () => {
    await loadSecurity();
  };

  useEffect(() => {
    loadDashboard();
  }, []);

  return {
    ...state,
    refreshDashboard,
    refreshStats,
    refreshActivities,
    refreshSecurity,
  };
};