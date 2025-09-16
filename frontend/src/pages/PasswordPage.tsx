// pages/PasswordsPage.tsx - FIXED VERSION with Vault Support
import React, { useState, useCallback } from 'react';
import { Search, Plus, RefreshCw, Shield ,Trash2, FolderOpen, CheckSquare, Square } from 'lucide-react';
import { useUnifiedTheme } from '../theme/UnifiedThemeProvider';
import {  type AddPasswordWithVaultData} from '../services/passwordService';

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

// Crear también el MasterPasswordModal
interface MasterPasswordModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSubmit: (masterPassword: string) => void;
  loading?: boolean;
  error?: string;
  title?: string;
  description?: string;
}

const MasterPasswordModal: React.FC<MasterPasswordModalProps> = ({
  isOpen,
  onClose,
  onSubmit,
  loading = false,
  error = '',
  title = "Confirmar Master Password",
  description = "Ingresa tu contraseña maestra para confirmar el cambio de contraseña"
}) => {
  const { colors } = useUnifiedTheme();
  const [masterPassword, setMasterPassword] = useState('');

  React.useEffect(() => {
    if (!isOpen) {
      setMasterPassword('');
    }
  }, [isOpen]);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (masterPassword.trim() && !loading) {
      onSubmit(masterPassword.trim());
    }
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 flex items-center justify-center p-4 z-50">
      <div 
        className="absolute inset-0"
        style={{
          backgroundColor: 'rgba(0, 0, 0, 0.4)',
          backdropFilter: 'blur(8px)',
        }}
        onClick={!loading ? onClose : undefined}
      />
      <div 
        className="relative max-w-md w-full rounded-2xl shadow-2xl border p-6"
        onClick={(e) => e.stopPropagation()}
        style={{ 
          backgroundColor: colors.surface,
          borderColor: colors.border,
        }}
      >
        <h3 className="text-lg font-semibold mb-2" style={{ color: colors.textPrimary }}>
          {title}
        </h3>
        <p className="text-sm mb-4" style={{ color: colors.textSecondary }}>
          {description}
        </p>

        <form onSubmit={handleSubmit} className="space-y-4">
          <input
            type="password"
            value={masterPassword}
            onChange={(e) => setMasterPassword(e.target.value)}
            placeholder="Contraseña maestra"
            className="w-full px-3 py-2 rounded-lg border focus:outline-none focus:ring-2"
            style={{
              backgroundColor: colors.background,
              borderColor: error ? colors.error : colors.border,
              color: colors.textPrimary
            }}
            disabled={loading}
            autoFocus
            required
          />

          {error && (
            <p className="text-sm" style={{ color: colors.error }}>
              {error}
            </p>
          )}

          <div className="flex gap-3">
            <button
              type="button"
              onClick={onClose}
              className="flex-1 px-4 py-2 rounded-lg border"
              style={{
                backgroundColor: colors.background,
                borderColor: colors.border,
                color: colors.textSecondary
              }}
              disabled={loading}
            >
              Cancelar
            </button>
            <button
              type="submit"
              className="flex-1 px-4 py-2 rounded-lg font-medium text-white"
              style={{ 
                backgroundColor: masterPassword.trim() ? colors.primary : colors.textMuted,
                opacity: masterPassword.trim() ? 1 : 0.5,
              }}
              disabled={loading || !masterPassword.trim()}
            >
              {loading ? 'Verificando...' : 'Confirmar'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

// Types and interfaces
interface PasswordsPageProps {
  onAddPassword?: () => void;
}

// Main component
export const PasswordsPage: React.FC<PasswordsPageProps> = ({ onAddPassword }) => {
  const { colors } = useUnifiedTheme();
  
  // 🔧 DEBUG: Agregar logs para debug
  console.log('🏠 PasswordsPage rendered');
  
  const {
    accounts,
    loading,
    error,
    unlockAccount,
    deleteAccount,
    updateAccount,
    createAccount
  } = usePasswordAccounts();

  // 🔧 DEBUG: Log cuando cambian las cuentas
  React.useEffect(() => {
    console.log('📊 Accounts updated in PasswordsPage:', accounts.length, 'accounts');
  }, [accounts]);

  // Local state
  const [searchTerm, setSearchTerm] = useState('');
  const [sortBy, setSortBy] = useState<'website' | 'username'>('website');
  const [toastMessage, setToastMessage] = useState<string | null>(null);

  
  // Modal states
  const [showUnlockModal, setShowUnlockModal] = useState(false);
  const [showDeleteModal, setShowDeleteModal] = useState(false);
  const [showAddModal, setShowAddModal] = useState(false);
  const [showEditModal, setShowEditModal] = useState(false);
  const [showMasterPasswordModal, setShowMasterPasswordModal] = useState(false);
  
  const [selectedAccount, setSelectedAccount] = useState<number | null>(null);
  
  // Error states
  const [unlockError, setUnlockError] = useState('');
  const [deleteError, setDeleteError] = useState('');
  const [addError, setAddError] = useState('');
  const [masterPasswordError, setMasterPasswordError] = useState('');
  
  // Loading states
  const [unlockLoading, setUnlockLoading] = useState(false);
  const [deleteLoading, setDeleteLoading] = useState(false);
  const [addLoading, setAddLoading] = useState(false);
  const [editLoading, setEditLoading] = useState(false);
  const [masterPasswordLoading, setMasterPasswordLoading] = useState(false);
  
  // CAMBIO CRÍTICO: Almacenar la master password real en lugar de solo un boolean
  const [validatedMasterPassword, setValidatedMasterPassword] = useState<string>('');
  
  // Edit flow state - Estado para manejar el flujo de edición
  const [pendingEditData, setPendingEditData] = useState<{
    accountId: number;
    data: EditPasswordData;
  } | null>(null);

  // Event handlers for unlock (for viewing passwords)
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

  // Event handlers for edit flow - Modificado para nuevo flujo
  const handleEdit = useCallback((accountId: number) => {
    setSelectedAccount(accountId);
    setShowEditModal(true);
    setValidatedMasterPassword(''); // Reset master password
  }, []);

  // Handler para cuando se requiere validación de master password desde EditPasswordModal
  const handleRequestMasterPassword = useCallback((accountId: number, formData: EditPasswordData) => {
    setPendingEditData({ accountId, data: formData });
    setShowEditModal(false); // Cerrar el modal de edición
    setShowMasterPasswordModal(true); // Abrir el modal de master password
    setMasterPasswordError('');
  }, []);

  // CAMBIO CRÍTICO: Almacenar la master password real después de validarla
  const handleMasterPasswordSubmit = useCallback(async (masterPassword: string) => {
    if (!pendingEditData) return;

    setMasterPasswordLoading(true);
    setMasterPasswordError('');
    
    try {
      // Validar la master password haciendo una operación simple (como desbloquear una cuenta)
      await unlockAccount(pendingEditData.accountId, masterPassword);
      
      // CRÍTICO: Almacenar la master password real
      setValidatedMasterPassword(masterPassword);
      setShowMasterPasswordModal(false);
      setShowEditModal(true); // Volver a abrir el modal de edición
      setPendingEditData(null); // Limpiar datos pendientes
    } catch (error) {
      setMasterPasswordError('Contraseña maestra incorrecta');
    } finally {
      setMasterPasswordLoading(false);
    }
  }, [pendingEditData, unlockAccount]);

  // CAMBIO CRÍTICO: Usar la master password real en lugar de un string 'validated'
  const handleEditSubmit = useCallback(async (
    accountId: number, 
    passwordData: EditPasswordData, 
    masterPassword?: string // Cambiar tipo de parámetro para coincidir con EditPasswordModal
  ) => {
    setEditLoading(true);
    
    try {
      // Si hay una master password validada y se está cambiando la contraseña, usarla
      const masterPasswordForUpdate = validatedMasterPassword && passwordData.password ? validatedMasterPassword : undefined;
      
      await updateAccount(accountId, passwordData, masterPasswordForUpdate);
      
      setShowEditModal(false);
      setValidatedMasterPassword(''); // Limpiar master password después del uso
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
      setToastMessage("Contraseña copiada ✓");
      setTimeout(() => setToastMessage(null), 2000); // se oculta en 2s
    });
  }, []);

  const handleAddPassword = useCallback(() => {
    console.log('➕ Add password button clicked');
    setShowAddModal(true);
    setAddError('');
    if (onAddPassword) {
      onAddPassword();
    }
  }, [onAddPassword]);

  // 🔧 CAMBIO CRÍTICO: Cambiar de AddPasswordData a AddPasswordWithVaultData
  const handleAddPasswordSubmit = useCallback(async (passwordData: AddPasswordWithVaultData) => {
    console.log('📝 handleAddPasswordSubmit called with:', {
      website: passwordData.website,
      username: passwordData.username,
      algorithm: passwordData.algorithm,
      vault_id: passwordData.vault_id,
      has_vault_password: !!passwordData.vault_password
    });
    
    setAddLoading(true);
    setAddError('');
    
    try {
      const result = await createAccount(passwordData);
      console.log('✅ createAccount result:', result);
      
      if (result.success) {
        setShowAddModal(false);
        setToastMessage("Contraseña creada exitosamente ✓");
        setTimeout(() => setToastMessage(null), 3000); 
        return { success: true};
      } else {
        setAddError(result.message || 'Error al crear la contraseña');
        return { success: false, error: result.message };
      }
    } catch (error) {
      console.error('❌ Error in handleAddPasswordSubmit:', error);
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
    setValidatedMasterPassword(''); // Limpiar master password
    setUnlockError('');
    setDeleteError('');
    setAddError('');
    setMasterPasswordError('');
  }, []);

  // Computed values
  const filteredAccounts = React.useMemo(() => {
    return accounts
      .filter(account => 
        account.website.toLowerCase().includes(searchTerm.toLowerCase()) ||
        account.username.toLowerCase().includes(searchTerm.toLowerCase())
      )
      .sort((a, b) => a[sortBy].localeCompare(b[sortBy]));
  }, [accounts, searchTerm, sortBy]);

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
            </h1>
            <p style={{ color: colors.textSecondary }}>
              Gestiona todas tus contraseñas de forma segura
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
            {searchTerm 
              ? 'Intenta con otros términos de búsqueda' 
              : 'Agrega tu primera contraseña para comenzar'
            }
          </p>
          {!searchTerm && (
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

      {toastMessage && (
        <div className="fixed bottom-6 right-6 bg-green-500 text-white px-4 py-2 rounded-lg shadow-lg animate-fade-in-out">
          {toastMessage}
        </div>
      )}

      
    </div>
  );
};