// pages/PasswordsPage.tsx - Updated with Vault Filtering
import React, { useState, useCallback, useEffect } from 'react';
import { Search, Plus, RefreshCw, Shield, Trash2, FolderOpen, CheckSquare, Lock, Folder } from 'lucide-react';
import { useUnifiedTheme } from '../components/UnifiedThemeProvider';
import { type AddPasswordWithVaultData } from '../components/account/AddPasswordModal';
import { vaultService, type Vault, VAULT_COLORS } from '../services/vaultService';
import { MasterPasswordModal } from '../components/account/MasterPasswordModal';
import { BatchDeleteModal } from '../components/account/BatchDeleteModal';
import { BatchMoveToVaultModal } from '../components/account/BatchMoveToVaultModal';

// Import componentized modules from the account components directory
import {
  UnlockModal,
  DeleteConfirmModal,
  AddPasswordModal,
  EditPasswordModal,
  AccountCard,
  type EditPasswordData,
  PasswordStats,
  usePasswordAccounts
} from '../components/account';

// Types and interfaces
interface PasswordsPageProps {
  onAddPassword?: () => void;
}

// Main component
export const PasswordsPage: React.FC<PasswordsPageProps> = ({ onAddPassword }) => {
  const { colors } = useUnifiedTheme();
  
  // NEW: Vault filtering state
  const [vaultFilter, setVaultFilter] = useState<string>('all');
  const [availableVaults, setAvailableVaults] = useState<Vault[]>([]);
  const [, setVaultsLoading] = useState(false);
  
  const {
    accounts,
    loading,
    error,
    unlockAccount,
    deleteAccount,
    updateAccount,
    createAccount,
    batchMovePasswords,
    batchDeletePasswords 
  } = usePasswordAccounts(vaultFilter === 'all' ? undefined : vaultFilter);

  // Load available vaults for filter
  useEffect(() => {
    const loadVaults = async () => {
      setVaultsLoading(true);
      try {
        const result = await vaultService.getVaults();
        setAvailableVaults(result.vaults || []);
      } catch (error) {
        console.error('Error loading vaults for filter:', error);
      } finally {
        setVaultsLoading(false);
      }
    };

    loadVaults();
  }, []);

  // Local state
  const [searchTerm, setSearchTerm] = useState('');
  const [sortBy, setSortBy] = useState<'website' | 'username'>('website');
  const [toastMessage, setToastMessage] = useState<string | null>(null);

  // Selection state
  const [selectedPasswords, setSelectedPasswords] = useState<Set<number>>(new Set());
  const [isSelectionMode, setIsSelectionMode] = useState(false);
  
  // Modal states
  const [showUnlockModal, setShowUnlockModal] = useState(false);
  const [showDeleteModal, setShowDeleteModal] = useState(false);
  const [showAddModal, setShowAddModal] = useState(false);
  const [showEditModal, setShowEditModal] = useState(false);
  const [showMasterPasswordModal, setShowMasterPasswordModal] = useState(false);
  const [showBatchDeleteModal, setShowBatchDeleteModal] = useState(false);
  const [showBatchMoveModal, setShowBatchMoveModal] = useState(false);

  const [selectedAccount, setSelectedAccount] = useState<number | null>(null);
  
  // Error states
  const [unlockError, setUnlockError] = useState('');
  const [deleteError, setDeleteError] = useState('');
  const [, setAddError] = useState('');
  const [masterPasswordError, setMasterPasswordError] = useState('');
  const [batchDeleteError, setBatchDeleteError] = useState('');
  const [batchMoveError, setBatchMoveError] = useState('');

  // Loading states
  const [unlockLoading, setUnlockLoading] = useState(false);
  const [deleteLoading, setDeleteLoading] = useState(false);
  const [addLoading, setAddLoading] = useState(false);
  const [editLoading, setEditLoading] = useState(false);
  const [masterPasswordLoading, setMasterPasswordLoading] = useState(false);
  const [batchDeleteLoading, setBatchDeleteLoading] = useState(false);
  const [batchMoveLoading, setBatchMoveLoading] = useState(false);

  const [validatedMasterPassword, setValidatedMasterPassword] = useState<string>('');
  
  // Edit flow state
  const [pendingEditData, setPendingEditData] = useState<{
    accountId: number;
    data: EditPasswordData;
  } | null>(null);

  // Clear selection when filter changes
  useEffect(() => {
    setSelectedPasswords(new Set());
    setIsSelectionMode(false);
  }, [vaultFilter]);

  // Computed values
  const filteredAccounts = React.useMemo(() => {
    return accounts
      .filter(account => 
        account.website.toLowerCase().includes(searchTerm.toLowerCase()) ||
        account.username.toLowerCase().includes(searchTerm.toLowerCase())
      )
      .sort((a, b) => a[sortBy].localeCompare(b[sortBy]));
  }, [accounts, searchTerm, sortBy]);

  // Get current vault info for display
  const getCurrentVaultInfo = () => {
    if (vaultFilter === 'all') return null;
    if (vaultFilter === 'unvaulted') return { name: 'Sin Vault', color: 'gray' as const };
    
    const vault = availableVaults.find(v => v.id.toString() === vaultFilter);
    return vault ? { name: vault.name, color: vault.color } : null;
  };

  const currentVaultInfo = getCurrentVaultInfo();

  const handleToggleSelection = useCallback((passwordId: number) => {
    setSelectedPasswords(prev => {
      const newSelection = new Set(prev);
      if (newSelection.has(passwordId)) {
        newSelection.delete(passwordId);
      } else {
        newSelection.add(passwordId);
      }
      
      if (newSelection.size === 0) {
        setIsSelectionMode(false);
      }
      
      return newSelection;
    });
  }, []);

  const handleClearSelection = useCallback(() => {
    setSelectedPasswords(new Set());
    setIsSelectionMode(false);
  }, []);

  const handleEnterSelectionMode = useCallback((passwordId?: number) => {
    setIsSelectionMode(true);
    if (passwordId) {
      setSelectedPasswords(new Set([passwordId]));
    }
  }, []);

  const handleBatchDelete = useCallback(() => {
    if (selectedPasswords.size > 0) {
      setShowBatchDeleteModal(true);
      setBatchDeleteError('');
    }
  }, [selectedPasswords.size]);

  const handleBatchDeleteConfirm = useCallback(async (masterPassword: string) => {
    setBatchDeleteLoading(true);
    setBatchDeleteError('');
    
    try {
      const passwordIds = Array.from(selectedPasswords);
      
      const result = await batchDeletePasswords(passwordIds, masterPassword);
      
      if (result.success) {
        setSelectedPasswords(new Set());
        setIsSelectionMode(false);
        setShowBatchDeleteModal(false);
        
        setToastMessage(`${passwordIds.length} contraseñas eliminadas exitosamente`);
        setTimeout(() => setToastMessage(null), 3000);
      }
      
    } catch (error) {
      console.error('Error in batch delete:', error);
      setBatchDeleteError('Error al eliminar las contraseñas');
    } finally {
      setBatchDeleteLoading(false);
    }
  }, [selectedPasswords, batchDeletePasswords]);

  const handleBatchMoveToVault = useCallback(() => {
    if (selectedPasswords.size > 0) {
      setShowBatchMoveModal(true);
      setBatchMoveError('');
    }
  }, [selectedPasswords.size]);

  const handleBatchMoveConfirm = useCallback(async (vaultId: number | null, vaultPassword?: string) => {
    setBatchMoveLoading(true);
    setBatchMoveError('');
    
    try {
      const passwordIds = Array.from(selectedPasswords);
      
      const result = await batchMovePasswords(passwordIds, vaultId, vaultPassword);
      
      if (result.success) {
        setSelectedPasswords(new Set());
        setIsSelectionMode(false);
        setShowBatchMoveModal(false);
        
        const vaultName = vaultId ? `vault ${vaultId}` : 'área general';
        setToastMessage(`${passwordIds.length} contraseñas movidas a ${vaultName}`);
        setTimeout(() => setToastMessage(null), 3000);
      }
      
    } catch (error) {
      console.error('Error in batch move:', error);
      setBatchMoveError('Error al mover las contraseñas');
    } finally {
      setBatchMoveLoading(false);
    }
  }, [selectedPasswords, batchMovePasswords]);

  // Event handlers for unlock
  const handleUnlock = useCallback((accountId: number) => {
    setSelectedAccount(accountId);
    setShowUnlockModal(true);
    setUnlockError('');
  }, []);

  const handleUnlockSubmit = useCallback(async (masterPassword: string) => {
    if (!selectedAccount) return;

    setUnlockLoading(true);
    setUnlockError('');
    
    try {
      await unlockAccount(selectedAccount, masterPassword);
      setShowUnlockModal(false);
      setSelectedAccount(null);
    } catch (error) {
      setUnlockError('Contraseña maestra incorrecta');
    } finally {
      setUnlockLoading(false);
    }
  }, [selectedAccount, unlockAccount]);

  // Event handlers for delete
  const handleDelete = useCallback((accountId: number) => {
    setSelectedAccount(accountId);
    setShowDeleteModal(true);
    setDeleteError('');
  }, []);

  const handleDeleteConfirm = useCallback(async (masterPassword: string) => {
    if (!selectedAccount) return;

    setDeleteLoading(true);
    setDeleteError('');
    
    try {
      await deleteAccount(selectedAccount, masterPassword);
      setShowDeleteModal(false);
      setSelectedAccount(null);
    } catch (error) {
      setDeleteError('Error al eliminar la contraseña');
    } finally {
      setDeleteLoading(false);
    }
  }, [selectedAccount, deleteAccount]);

  // Event handlers for edit flow
  const handleEdit = useCallback((accountId: number) => {
    setSelectedAccount(accountId);
    setShowEditModal(true);
    setValidatedMasterPassword('');
  }, []);

  const handleRequestMasterPassword = useCallback((accountId: number, formData: EditPasswordData) => {
    setPendingEditData({ accountId, data: formData });
    setShowEditModal(false);
    setShowMasterPasswordModal(true);
    setMasterPasswordError('');
  }, []);

  const handleMasterPasswordSubmit = useCallback(async (masterPassword: string) => {
    if (!pendingEditData) return;

    setMasterPasswordLoading(true);
    setMasterPasswordError('');
    
    try {
      await unlockAccount(pendingEditData.accountId, masterPassword);
      
      setValidatedMasterPassword(masterPassword);
      setShowMasterPasswordModal(false);
      setShowEditModal(true);
      setPendingEditData(null);
    } catch (error) {
      setMasterPasswordError('Contraseña maestra incorrecta');
    } finally {
      setMasterPasswordLoading(false);
    }
  }, [pendingEditData, unlockAccount]);

  const handleEditSubmit = useCallback(async (
    accountId: number,
    passwordData: EditPasswordData,
    _masterPassword?: string
  ) => {
    setEditLoading(true);
    
    try {
      const masterPasswordForUpdate = validatedMasterPassword && passwordData.password ? validatedMasterPassword : undefined;
      
      await updateAccount(accountId, passwordData, masterPasswordForUpdate);
      
      setShowEditModal(false);
      setValidatedMasterPassword('');
      return { success: true };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Error al actualizar la contraseña';
      return { success: false, error: errorMessage };
    } finally {
      setEditLoading(false);
    }
  }, [updateAccount, validatedMasterPassword]);

  const handleCopy = useCallback((password: string) => {
    navigator.clipboard.writeText(password).then(() => {
      setToastMessage("Contraseña copiada");
      setTimeout(() => setToastMessage(null), 2000);
    });
  }, []);

  const handleAddPassword = useCallback(() => {
    setShowAddModal(true);
    setAddError('');
    if (onAddPassword) {
      onAddPassword();
    }
  }, [onAddPassword]);

  const handleAddPasswordSubmit = useCallback(async (passwordData: AddPasswordWithVaultData) => {
    setAddLoading(true);
    setAddError('');
    
    try {
      const result = await createAccount(passwordData);
      
      if (result.success) {
        setShowAddModal(false);
        setToastMessage("Contraseña creada exitosamente");
        setTimeout(() => setToastMessage(null), 3000); 
        return { success: true };
      } else {
        setAddError(result.message || 'Error al crear la contraseña');
        return { success: false, error: result.message };
      }
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Error al crear la contraseña';
      setAddError(errorMessage);
      return { success: false, error: errorMessage };
    } finally {
      setAddLoading(false);
    }
  }, [createAccount]);

  const handleCloseModals = useCallback(() => {
    setShowUnlockModal(false);
    setShowDeleteModal(false);
    setShowAddModal(false);
    setShowEditModal(false);
    setShowMasterPasswordModal(false);
    setSelectedAccount(null);
    setPendingEditData(null);
    setShowBatchMoveModal(false);
    setShowBatchDeleteModal(false);
    setValidatedMasterPassword('');
    setUnlockError('');
    setDeleteError('');
    setAddError('');
    setMasterPasswordError('');
    setBatchDeleteError('');
    setBatchMoveError('');
  }, []);

  const selectedAccountData = accounts.find(acc => acc.id === selectedAccount);

  // Loading state
  if (loading) {
    return (
      <div 
        className="password-loading"
        style={{ backgroundColor: colors.background }}
      >
        <div className="password-loading-content">
          <RefreshCw 
            className="password-loading-spinner animate-spin" 
            style={{ color: colors.primary }} 
          />
          <p style={{ color: colors.textSecondary }}>Cargando contraseñas...</p>
        </div>
      </div>
    );
  }

  // Error state
  if (error) {
    return (
      <div 
        className="password-loading"
        style={{ backgroundColor: colors.background }}
      >
        <div className="password-loading-content">
          <p style={{ color: colors.error }}>{error}</p>
          <button
            onClick={() => window.location.reload()}
            className="password-add-button"
            style={{ backgroundColor: colors.primary, marginTop: '1rem' }}
          >
            Reintentar
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="password-page-container" style={{ backgroundColor: colors.background }}>
      {/* Header */}
      <div className="password-header">
        <div className="password-header-content">
          <div className="password-header-info">
            <h1 style={{ color: colors.textPrimary }}>
              Contraseñas Guardadas
              {currentVaultInfo && (
                <span 
                  className="ml-3 px-3 py-1 rounded-full text-sm font-medium inline-flex items-center space-x-1"
                  style={{
                    backgroundColor: `${VAULT_COLORS[currentVaultInfo.color].bg}20`,
                    color: VAULT_COLORS[currentVaultInfo.color].text,
                    border: `1px solid ${VAULT_COLORS[currentVaultInfo.color].border}`
                  }}
                >
                  {vaultFilter === 'unvaulted' ? (
                    <Folder className="w-4 h-4" />
                  ) : (
                    <Lock className="w-4 h-4" />
                  )}
                  <span>{currentVaultInfo.name}</span>
                </span>
              )}
            </h1>
            <p style={{ color: colors.textSecondary }}>
              {currentVaultInfo 
                ? `Contraseñas en ${currentVaultInfo.name.toLowerCase()}`
                : 'Gestiona todas tus contraseñas de forma segura'
              }
            </p>
          </div>

          <button
            className="password-add-button"
            style={{ backgroundColor: colors.primary }}
            onClick={handleAddPassword}
          >
            <Plus className="w-5 h-5" />
            Agregar Contraseña
          </button>
        </div>

        {/* Search and Filter Bar */}
        <div className="password-search-bar">
          <div className="password-search-input-container">
            <Search 
              className="password-search-icon" 
              style={{ color: colors.textMuted }} 
            />
            <input
              type="text"
              placeholder="Buscar por sitio web o usuario..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="password-search-input"
              style={{
                backgroundColor: colors.surface,
                borderColor: colors.border,
                color: colors.textPrimary
              }}
            />
          </div>

          {/* NEW: Vault Filter Dropdown */}
            
            <select
              value={vaultFilter}
              onChange={(e) => setVaultFilter(e.target.value)}
              className="password-sort-select"
              style={{
                backgroundColor: colors.surface,
                borderColor: colors.border,
                color: colors.textPrimary
              }}
            >
              <option value="all">Todas las contraseñas</option>
              <option value="unvaulted">Sin Vault</option>
              {availableVaults.map(vault => (
                <option key={vault.id} value={vault.id.toString()}>
                  {vault.is_private ? '🔒 ' : '📁 '}{vault.name} ({vault.password_count})
                </option>
              ))}
            </select>
          

          <select
            value={sortBy}
            onChange={(e) => setSortBy(e.target.value as 'website' | 'username')}
            className="password-sort-select"
            style={{
              backgroundColor: colors.surface,
              borderColor: colors.border,
              color: colors.textPrimary
            }}
          >
            <option value="website">Ordenar por Sitio Web</option>
            <option value="username">Ordenar por Usuario</option>
          </select>
        </div>
      </div>

      {/* Stats */}
      <PasswordStats accounts={accounts} />

      {/* Selection Controls */}
      {filteredAccounts.length > 0 && (
        <div className="password-selection-controls">
          {isSelectionMode ? (
            <div className="password-selection-active">
              <span className="password-selection-counter">
                {selectedPasswords.size} seleccionadas
              </span>
              
              {selectedPasswords.size > 0 && (
                <>
                  <button
                    className="password-selection-delete-btn"
                    onClick={handleBatchDelete}
                  >
                    <Trash2 className="w-4 h-4" />
                    Eliminar ({selectedPasswords.size})
                  </button>
                  
                  <button
                    className="password-selection-move-btn"
                    onClick={handleBatchMoveToVault}
                  >
                    <FolderOpen className="w-4 h-4" />
                    Mover a Vault
                  </button>
                </>
              )}
              
              <button
                className="password-selection-cancel-btn"
                onClick={handleClearSelection}
              >
                Cancelar
              </button>
            </div>
          ) : (
            <div className="password-selection-inactive">
              <button
                className="password-selection-enter-btn"
                onClick={() => handleEnterSelectionMode()}
              >
                <CheckSquare className="w-4 h-4" />
                Seleccionar
              </button>
            </div>
          )}
        </div>
      )}

      {/* Password Cards */}
      {filteredAccounts.length > 0 ? (
        <div className="password-cards-grid">
          {filteredAccounts.map(account => (
            <AccountCard
              key={account.id}
              account={account}
              onUnlock={handleUnlock}
              onEdit={handleEdit}
              onDelete={handleDelete}
              onCopy={handleCopy}
              isUnlocked={Boolean(account.decrypted_password)}
              isSelectionMode={isSelectionMode}
              isSelected={selectedPasswords.has(account.id)}
              onToggleSelection={handleToggleSelection}
              onEnterSelectionMode={handleEnterSelectionMode}
            />
          ))}
        </div>
      ) : (
        <div className="password-empty-state">
          <Shield 
            className="password-empty-icon" 
            style={{ color: colors.textMuted }} 
          />
          <h3 
            className="password-empty-title"
            style={{ color: colors.textPrimary }}
          >
            No se encontraron contraseñas
          </h3>
          <p 
            className="password-empty-description"
            style={{ color: colors.textSecondary }}
          >
            {searchTerm || vaultFilter !== 'all'
              ? 'Intenta con otros términos de búsqueda o cambia el filtro' 
              : 'Agrega tu primera contraseña para comenzar'
            }
          </p>
          {!searchTerm && vaultFilter === 'all' && (
            <button
              onClick={handleAddPassword}
              className="password-add-button mt-4"
              style={{ backgroundColor: colors.primary }}
            >
              <Plus className="w-5 h-5" />
              Agregar Primera Contraseña
            </button>
          )}
        </div>
      )}

      {/* Modals */}
      <UnlockModal
        isOpen={showUnlockModal}
        onClose={handleCloseModals}
        onSubmit={handleUnlockSubmit}
        loading={unlockLoading}
        error={unlockError}
      />

      <DeleteConfirmModal
        isOpen={showDeleteModal}
        onClose={handleCloseModals}
        onConfirm={handleDeleteConfirm}
        accountName={selectedAccountData?.website || ''}
        loading={deleteLoading}
        error={deleteError}
      />

      <AddPasswordModal
        isOpen={showAddModal}
        onClose={handleCloseModals}
        onSubmit={handleAddPasswordSubmit}
        loading={addLoading}
      />

      <EditPasswordModal
        isOpen={showEditModal}
        onClose={handleCloseModals}
        onSubmit={handleEditSubmit}
        onRequestMasterPassword={handleRequestMasterPassword}
        account={selectedAccountData || null}
        loading={editLoading}
        masterPasswordValidated={Boolean(validatedMasterPassword)}
      />

      <MasterPasswordModal
        isOpen={showMasterPasswordModal}
        onClose={handleCloseModals}
        onSubmit={handleMasterPasswordSubmit}
        loading={masterPasswordLoading}
        error={masterPasswordError}
        title="Validar Contraseña Maestra"
        description="Ingresa tu contraseña maestra para autorizar el cambio de contraseña"
      />

      <BatchDeleteModal
        isOpen={showBatchDeleteModal}
        onClose={handleCloseModals}
        onConfirm={handleBatchDeleteConfirm}
        selectedCount={selectedPasswords.size}
        loading={batchDeleteLoading}
        error={batchDeleteError}
      />

      <BatchMoveToVaultModal
        isOpen={showBatchMoveModal}
        onClose={handleCloseModals}
        onConfirm={handleBatchMoveConfirm}
        selectedCount={selectedPasswords.size}
        loading={batchMoveLoading}
        error={batchMoveError}
      />

      {toastMessage && (
        <div className="fixed bottom-6 right-6 bg-green-500 text-white px-4 py-2 rounded-lg shadow-lg animate-fade-in-out">
          {toastMessage}
        </div>
      )}
    </div>
  );
};