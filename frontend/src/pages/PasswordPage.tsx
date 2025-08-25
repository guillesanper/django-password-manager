// pages/PasswordsPage.tsx
import React, { useState, useCallback } from 'react';
import { Search, Plus, RefreshCw, Shield } from 'lucide-react';
import { useUnifiedTheme } from '../theme/UnifiedThemeProvider';

// Import componentized modules from the account components directory
import {
  UnlockModal,
  DeleteConfirmModal,
  AddPasswordModal,
  AccountCard,
  type PasswordAccount,
  type AddPasswordData,
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
  const {
    accounts,
    loading,
    error,
    unlockAccount,
    deleteAccount,
    createAccount
  } = usePasswordAccounts();

  // Local state
  const [searchTerm, setSearchTerm] = useState('');
  const [sortBy, setSortBy] = useState<'website' | 'username'>('website');
  const [showUnlockModal, setShowUnlockModal] = useState(false);
  const [showDeleteModal, setShowDeleteModal] = useState(false);
  const [showAddModal, setShowAddModal] = useState(false);
  const [selectedAccount, setSelectedAccount] = useState<number | null>(null);
  const [unlockError, setUnlockError] = useState('');
  const [deleteError, setDeleteError] = useState('');
  const [addError, setAddError] = useState('');
  const [unlockLoading, setUnlockLoading] = useState(false);
  const [deleteLoading, setDeleteLoading] = useState(false);
  const [addLoading, setAddLoading] = useState(false);

  // Event handlers
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

  const handleEdit = useCallback((accountId: number) => {
    // TODO: Implement navigation to edit page
    console.log('Edit account:', accountId);
  }, []);

  const handleCopy = useCallback((password: string) => {
    // TODO: Show success notification
    console.log('Password copied to clipboard');
  }, []);

  const handleAddPassword = useCallback(() => {
    setShowAddModal(true);
    setAddError('');
    // También llamar al prop si existe (para compatibilidad)
    if (onAddPassword) {
      onAddPassword();
    }
  }, [onAddPassword]);

  const handleAddPasswordSubmit = useCallback(async (passwordData: AddPasswordData) => {
    setAddLoading(true);
    setAddError('');
    
    try {
      await createAccount(passwordData);
      return { success: true };
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
    setSelectedAccount(null);
    setUnlockError('');
    setDeleteError('');
    setAddError('');
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
    </div>
  );
};

export default PasswordsPage;