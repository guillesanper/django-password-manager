// hooks/useVaults.ts - Hook personalizado mejorado para manejar vaults
import { useState, useEffect, useCallback, createContext, useContext } from 'react';
import type { ReactNode } from 'react';
import { vaultService } from '../../services/vaultService';
import type { CreateVaultData, UpdateVaultData, Vault } from '../../services/vaultService';

// Contexto para compartir el estado de vaults globalmente
interface VaultContextType {
  vaults: Vault[];
  unvaultedCount: number;
  loading: boolean;
  error: string | null;
  selectedVaultId: number | null;
  unlockedVaults: Set<number>;
  // Funciones principales
  createVault: (vaultData: CreateVaultData) => Promise<{ success: boolean; message?: string }>;
  updateVault: (vaultId: number, updates: UpdateVaultData) => Promise<{ success: boolean; message?: string }>;
  deleteVault: (vaultId: number, masterPassword: string, movePasswordsToVault?: number) => Promise<{ success: boolean; message?: string }>;
  unlockVault: (vaultId: number, vaultPassword: string) => Promise<{ success: boolean; message?: string }>;
  selectVault: (vaultId: number | null) => void;
  // Gestión de contraseñas
  movePasswordToVault: (passwordId: number, vaultId: number | null, vaultPassword?: string) => Promise<{ success: boolean; message?: string }>;
  batchMovePasswords: (passwordIds: number[], destinationVaultId: number | null, vaultPassword?: string) => Promise<{ success: boolean; message?: string }>;
  getVaultPasswords: (vaultId: number) => Promise<any>;
  getUnvaultedPasswords: () => Promise<any>;
  // Utilidades
  reloadVaults: () => Promise<void>;
  getVaultById: (vaultId: number) => Vault | null;
  hasPrivateVaults: () => boolean;
  getVaultStats: () => Promise<any>;
  clearSelection: () => void;
  // Gestion de Unlocked Vaults
  isVaultUnlocked: (vaultId: number) => boolean;
  markVaultAsUnlocked: (vaultId: number) => void;
  lockVault: (vaultId: number) => void;
  lockAllVaults: () => void;

}

const VaultContext = createContext<VaultContextType | null>(null);

// Props para el Provider
interface VaultProviderProps {
  children: ReactNode;
}

// Hook interno con toda la lógica
const useVaultsInternal = (): VaultContextType => {
  const [vaults, setVaults] = useState<Vault[]>([]);
  const [unvaultedCount, setUnvaultedCount] = useState<number>(0);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedVaultId, setSelectedVaultId] = useState<number | null>(null);
  const [unlockedVaults, setUnlockedVaults] = useState<Set<number>>(new Set());


  // Cargar vaults del servidor
  const loadVaults = useCallback(async (): Promise<void> => {
    setLoading(true);
    setError(null);
    
    try {
      const result = await vaultService.getVaults();
      setVaults(result.vaults);
      setUnvaultedCount(result.unvaulted_passwords);
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Error al cargar los vaults';
      setError(errorMessage);
      console.error('Error loading vaults:', err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadVaults();
  }, [loadVaults]);

  // Crear un nuevo vault
  const createVault = useCallback(async (vaultData: CreateVaultData): Promise<{ success: boolean; message?: string }> => {
    try {
      setError(null);
      const result = await vaultService.createVault(vaultData);
      
      if (result.success && result.data) {
        
        const newVault = result.data;
        // Agregar el nuevo vault al estado local
        setVaults(prev => [...prev, newVault]);
        
        // Log para debugging
        console.log('Vault creado exitosamente:', result.data);
        
        return { success: true, message: result.message || 'Vault creado exitosamente' };
      } else {
        throw new Error(result.error || 'Error al crear el vault');
      }
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Error al crear el vault';
      console.error('Error creating vault:', err);
      setError(errorMessage);
      throw new Error(errorMessage);
    }
  }, []);

  // Actualizar un vault existente
  const updateVault = useCallback(async (vaultId: number, updates: UpdateVaultData): Promise<{ success: boolean; message?: string }> => {
    try {
      setError(null);
      const result = await vaultService.updateVault(vaultId, updates);
      
      if (result.success && result.data) {
        // Actualizar el vault en el estado local
        setVaults(prev => prev.map(vault => 
          vault.id === vaultId ? { ...vault, ...result.data } : vault
        ));
        
        console.log('Vault actualizado exitosamente:', result.data);
        
        return { success: true, message: result.message || 'Vault actualizado exitosamente' };
      } else {
        throw new Error(result.error || 'Error al actualizar el vault');
      }
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Error al actualizar el vault';
      console.error('Error updating vault:', err);
      setError(errorMessage);
      throw new Error(errorMessage);
    }
  }, []);

  // Eliminar un vault
  const deleteVault = useCallback(async (
    vaultId: number, 
    masterPassword: string,
    movePasswordsToVault?: number
  ): Promise<{ success: boolean; message?: string }> => {
    try {
      setError(null);
      const result = await vaultService.deleteVault(vaultId, masterPassword, movePasswordsToVault);
      
      if (result.success) {
        // Eliminar el vault del estado local
        setVaults(prev => prev.filter(vault => vault.id !== vaultId));
        
        // Si el vault eliminado estaba seleccionado, deseleccionar
        if (selectedVaultId === vaultId) {
          setSelectedVaultId(null);
        }
        
        // Recargar para actualizar conteos
        await loadVaults();
        
        console.log('Vault eliminado exitosamente');
        
        return { success: true, message: result.message || 'Vault eliminado exitosamente' };
      } else {
        throw new Error(result.error || 'Error al eliminar el vault');
      }
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Error al eliminar el vault';
      console.error('Error deleting vault:', err);
      setError(errorMessage);
      throw new Error(errorMessage);
    }
  }, [selectedVaultId, loadVaults]);

  // Desbloquear un vault privado
  const unlockVault = useCallback(async (vaultId: number, vaultPassword: string): Promise<{ success: boolean; message?: string }> => {
    try {
      setError(null);
      const result = await vaultService.unlockVault(vaultId, vaultPassword);
      
      if (result.success) {
        // Seleccionar el vault desbloqueado
        setSelectedVaultId(vaultId);
        setUnlockedVaults(prev => new Set(prev).add(vaultId));

        console.log('Vault desbloqueado exitosamente');
        
        return { success: true, message: result.message || 'Vault desbloqueado exitosamente' };
      } else {
        throw new Error(result.error || 'Error al desbloquear el vault');
      }
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Error al desbloquear el vault';
      console.error('Error unlocking vault:', err);
      setError(errorMessage);
      throw new Error(errorMessage);
    }
  }, []);

  // Funciones para gestionar vaults desbloqueados
  const isVaultUnlocked = useCallback((vaultId: number): boolean => {
    return unlockedVaults.has(vaultId);
  }, [unlockedVaults]);

  const markVaultAsUnlocked = useCallback((vaultId: number): void => {
    setUnlockedVaults(prev => new Set(prev).add(vaultId));
    console.log('Vault marcado como desbloqueado:', vaultId);
  }, []);

  const lockVault = useCallback((vaultId: number): void => {
    setUnlockedVaults(prev => {
      const newSet = new Set(prev);
      newSet.delete(vaultId);
      return newSet;
    });
    
    if (selectedVaultId === vaultId) {
      setSelectedVaultId(null);
    }
    
    console.log('Vault bloqueado:', vaultId);
  }, [selectedVaultId]);

  const lockAllVaults = useCallback((): void => {
    setUnlockedVaults(new Set());
    setSelectedVaultId(null);
    console.log('Todos los vaults bloqueados');
  }, []);


  // Mover contraseña a vault
  const movePasswordToVault = useCallback(async (
    passwordId: number, 
    vaultId: number | null,
    vaultPassword?: string
  ): Promise<{ success: boolean; message?: string }> => {
    try {
      setError(null);
      const result = await vaultService.movePasswordToVault(passwordId, vaultId, vaultPassword);
      
      if (result.success) {
        // Recargar vaults para actualizar conteos
        await loadVaults();
        
        console.log('Contraseña movida exitosamente');
        
        return { success: true, message: result.message || 'Contraseña movida exitosamente' };
      } else {
        throw new Error(result.error || 'Error al mover la contraseña');
      }
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Error al mover la contraseña';
      console.error('Error moving password:', err);
      setError(errorMessage);
      throw new Error(errorMessage);
    }
  }, [loadVaults]);

  // Mover múltiples contraseñas
  const batchMovePasswords = useCallback(async (
    passwordIds: number[], 
    destinationVaultId: number | null,
    vaultPassword?: string
  ): Promise<{ success: boolean; message?: string }> => {
    try {
      setError(null);
      const result = await vaultService.batchMovePasswords(passwordIds, destinationVaultId, vaultPassword);
      
      if (result.success) {
        // Recargar vaults para actualizar conteos
        await loadVaults();
        
        console.log('Contraseñas movidas exitosamente');
        
        return { success: true, message: result.message || 'Contraseñas movidas exitosamente' };
      } else {
        throw new Error(result.error || 'Error al mover las contraseñas');
      }
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Error al mover las contraseñas';
      console.error('Error batch moving passwords:', err);
      setError(errorMessage);
      throw new Error(errorMessage);
    }
  }, [loadVaults]);

  // Obtener contraseñas de un vault específico
  const getVaultPasswords = useCallback(async (vaultId: number): Promise<any> => {
    try {
      setError(null);
      const result = await vaultService.getVaultPasswords(vaultId);
      
      if (result.success) {
        console.log('Contraseñas del vault obtenidas exitosamente');
        
        return {
          success: true,
          vault: result.vault,
          passwords: result.passwords,
          count: result.count
        };
      } else {
        throw new Error(result.error || 'Error al cargar las contraseñas del vault');
      }
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Error al cargar las contraseñas del vault';
      console.error('Error getting vault passwords:', err);
      setError(errorMessage);
      throw new Error(errorMessage);
    }
  }, []);

  // Obtener contraseñas sin vault
  const getUnvaultedPasswords = useCallback(async (): Promise<any> => {
    try {
      setError(null);
      const result = await vaultService.getUnvaultedPasswords();
      
      if (result.success) {
        console.log('Contraseñas sin vault obtenidas exitosamente');
        
        return {
          success: true,
          passwords: result.passwords,
          count: result.count
        };
      } else {
        throw new Error(result.error || 'Error al cargar las contraseñas sin vault');
      }
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Error al cargar las contraseñas sin vault';
      console.error('Error getting unvaulted passwords:', err);
      setError(errorMessage);
      throw new Error(errorMessage);
    }
  }, []);

  // Seleccionar vault
  const selectVault = useCallback((vaultId: number | null): void => {
    setSelectedVaultId(vaultId);
    console.log('Vault seleccionado:', vaultId);
  }, []);

  // Obtener vault por ID
  const getVaultById = useCallback((vaultId: number): Vault | null => {
    return vaults.find(vault => vault.id === vaultId) || null;
  }, [vaults]);

  // Verificar si hay vaults privados
  const hasPrivateVaults = useCallback((): boolean => {
    return vaults.some(vault => vault.is_private);
  }, [vaults]);

  // Obtener estadísticas
  const getVaultStats = useCallback(async (): Promise<any> => {
    try {
      setError(null);
      const result = await vaultService.getVaultStats();
      
      if (result.success) {
        console.log('Estadísticas obtenidas exitosamente');
        return result.stats;
      } else {
        throw new Error(result.error || 'Error al cargar estadísticas');
      }
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Error al cargar estadísticas';
      console.error('Error getting vault stats:', err);
      setError(errorMessage);
      throw new Error(errorMessage);
    }
  }, []);

  // Limpiar errores cuando se cambia de vault
  useEffect(() => {
    if (error) {
      const timer = setTimeout(() => {
        setError(null);
      }, 5000);
      return () => clearTimeout(timer);
    }
  }, [error]);

  return {
    // Estado
    vaults,
    unvaultedCount,
    loading,
    error,
    selectedVaultId,
    unlockedVaults,
    
    // Acciones principales
    createVault,
    updateVault,
    deleteVault,
    unlockVault,
    selectVault,
    
    // Gestión de contraseñas
    movePasswordToVault,
    batchMovePasswords,
    getVaultPasswords,
    getUnvaultedPasswords,
    
    // Utilidades
    reloadVaults: loadVaults,
    getVaultById,
    hasPrivateVaults,
    getVaultStats,

    // Gestión de vaults desbloqueados
    isVaultUnlocked,
    markVaultAsUnlocked,
    lockVault,
    lockAllVaults,
    
    // Limpiar selección
    clearSelection: () => setSelectedVaultId(null)
  };
};

// Provider del contexto - Función normal sin JSX
export function VaultProvider({ children }: { children: ReactNode }) {
  const vaultState = useVaultsInternal();

  return (
    <VaultContext.Provider value={vaultState}>
      {children}
    </VaultContext.Provider>
  );
}


// Hook público que consume el contexto
export const useVaults = (): VaultContextType => {
  const context = useContext(VaultContext);
  
  if (!context) {
    // Si no hay contexto, crear un estado local temporal
    // Esto es útil para desarrollo y testing
    console.warn('useVaults usado fuera del VaultProvider, creando estado local');
    return useVaultsInternal();
  }
  
  return context;
};

// Hook específico para el sidebar que incluye funcionalidades adicionales
export const useVaultSidebar = () => {
  const vaultContext = useVaults();
  const [sidebarState, setSidebarState] = useState({
    activeVaultActions: null as number | null,
    showCreateModal: false,
    showManageModal: false,
    vaultToManage: null as Vault | null
  });

  // Funciones específicas del sidebar
  const handleVaultSelect = useCallback((vaultId: number | null): void => {
    vaultContext.selectVault(vaultId);
    setSidebarState(prev => ({ ...prev, activeVaultActions: null }));
  }, [vaultContext]);

  const showVaultActions = useCallback((vaultId: number | null): void => {
    setSidebarState(prev => ({ 
      ...prev, 
      activeVaultActions: prev.activeVaultActions === vaultId ? null : vaultId 
    }));
  }, []);

  const hideVaultActions = useCallback((): void => {
    setSidebarState(prev => ({ ...prev, activeVaultActions: null }));
  }, []);

  const showCreateVault = useCallback((): void => {
    setSidebarState(prev => ({ ...prev, showCreateModal: true }));
  }, []);

  const hideCreateVault = useCallback((): void => {
    setSidebarState(prev => ({ ...prev, showCreateModal: false }));
  }, []);

  const showManageVault = useCallback((vault: Vault): void => {
    setSidebarState(prev => ({ 
      ...prev, 
      showManageModal: true, 
      vaultToManage: vault,
      activeVaultActions: null
    }));
  }, []);

  const hideManageVault = useCallback((): void => {
    setSidebarState(prev => ({ 
      ...prev, 
      showManageModal: false, 
      vaultToManage: null 
    }));
  }, []);

  // Cerrar menús con Escape
  useEffect(() => {
    const handleEscape = (event: KeyboardEvent): void => {
      if (event.key === 'Escape') {
        hideVaultActions();
      }
    };

    document.addEventListener('keydown', handleEscape);
    return () => document.removeEventListener('keydown', handleEscape);
  }, [hideVaultActions]);

  return {
    ...vaultContext,
    ...sidebarState,
    // Funciones específicas del sidebar
    handleVaultSelect,
    showVaultActions,
    hideVaultActions,
    showCreateVault,
    hideCreateVault,
    showManageVault,
    hideManageVault
  };
};