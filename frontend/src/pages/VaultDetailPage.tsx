import React, { useState, useEffect, useCallback } from 'react';
import { Search, Plus, RefreshCw, Shield, ArrowLeft, Lock, Folder, Trash2, Settings } from 'lucide-react';
import { useUnifiedTheme } from '../components/UnifiedThemeProvider';
import { vaultService, VAULT_COLORS, type Vault } from '../services/vaultService';
import { passwordService } from '../services/passwordService';
import { type PasswordAccount } from '../components/account/AccountCard';
import { type AddPasswordWithVaultData } from '../components/account/AddPasswordModal';
import { VaultPasswordCard } from '../components/vaults/VaultPasswordCard';
import { UnlockVaultModal } from '../components/vaults/UnlockVaultModal';
import { UnlockModal } from '../components/account/UnlockModal';
import { DeleteConfirmModal } from '../components/account/DeleteConfirmModal';
import { AddPasswordModal, type AddPasswordData } from '../components/account/AddPasswordModal';
import { EditPasswordModal, type EditPasswordData } from '../components/account/EditPasswordModal';
import { DeleteVaultModal } from '../components/vaults/DeleteVaultModal';
import { ManageVaultModal } from '../components/vaults/ManageVaultModal';
import { useVaults } from '../components/hooks/useVaults';

interface VaultDetailPageProps {
  vaultId: number;
  onBack: () => void;
}

export const VaultDetailPage: React.FC<VaultDetailPageProps> = ({ vaultId, onBack }) => {
  const { colors } = useUnifiedTheme();
  const { vaults, reloadVaults, isVaultUnlocked, markVaultAsUnlocked } = useVaults();
  
  // Estados principales
  const [vault, setVault] = useState<Vault | null>(null);
  const [passwords, setPasswords] = useState<PasswordAccount[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  
  // Estados de búsqueda y filtrado
  const [searchTerm, setSearchTerm] = useState('');
  const [sortBy, setSortBy] = useState<'website' | 'username'>('website');
  const [toastMessage, setToastMessage] = useState<string | null>(null);

  // Estados de modales para contraseñas
  const [showUnlockVaultModal, setShowUnlockVaultModal] = useState(false);
  const [showUnlockPasswordModal, setShowUnlockPasswordModal] = useState(false);
  const [showDeleteModal, setShowDeleteModal] = useState(false);
  const [showAddModal, setShowAddModal] = useState(false);
  const [showEditModal, setShowEditModal] = useState(false);
  
  // Estados de modales para vault management
  const [showManageVaultModal, setShowManageVaultModal] = useState(false);
  const [showDeleteVaultModal, setShowDeleteVaultModal] = useState(false);
  
  const [selectedAccount, setSelectedAccount] = useState<number | null>(null);
  
  // Estados de error y carga
  const [, setUnlockVaultError] = useState('');
  const [unlockPasswordError, setUnlockPasswordError] = useState('');
  const [deleteError, setDeleteError] = useState('');
  const [, setAddError] = useState('');
  
  const [unlockVaultLoading, setUnlockVaultLoading] = useState(false);
  const [unlockPasswordLoading, setUnlockPasswordLoading] = useState(false);
  const [deleteLoading, setDeleteLoading] = useState(false);
  const [addLoading, setAddLoading] = useState(false);
  const [editLoading, setEditLoading] = useState(false);

  // Cargar datos del vault y sus contraseñas
  const loadVaultData = useCallback(async () => {
    setLoading(true);
    setError(null);
    
    try {
      const result = await vaultService.getVaultPasswords(vaultId);
      
      if (result.success && result.vault && result.passwords) {
        setVault(result.vault);
        setPasswords(result.passwords);
        
        // Si el vault es público, marcarlo como desbloqueado
        if (!result.vault.is_private) {
          markVaultAsUnlocked(result.vault.id);
        } else if (!isVaultUnlocked(result.vault.id)) {
          setShowUnlockVaultModal(false);
        }
      } else {
        throw new Error(result.error || 'Error al cargar el vault');
      }
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Error al cargar el vault';
      setError(errorMessage);
      console.error('Error loading vault data:', err);
    } finally {
      setLoading(false);
    }
  }, [vaultId]);

  useEffect(() => {
    loadVaultData();
  }, [loadVaultData]);

  // Handlers para gestión del vault
  const handleEditVault = useCallback((vault: Vault) => {
    setShowManageVaultModal(false);
    // Aquí puedes abrir un modal específico de edición si lo tienes
    // o redirigir a donde tengas la funcionalidad de edición
    console.log('Edit vault:', vault);
  }, []);

  const handleDeleteVault = useCallback((_vault: Vault) => {
    setShowManageVaultModal(false);
    setShowDeleteVaultModal(true);
  }, []);


  const reloadPasswords = useCallback(async () => {
  try {
    const result = await vaultService.getVaultPasswords(vaultId);
    
    if (result.success && result.passwords) {
      setPasswords(result.passwords);
      
      // Actualizar el contador en el vault si viene en la respuesta
      if (result.vault && typeof result.vault.password_count !== 'undefined' && vault) {
        setVault(prev => prev ? { ...prev, password_count: result.vault!.password_count } : prev);
      }
    }
  } catch (err) {
    console.error('Error reloading passwords:', err);
  }
}, [vaultId, vault]);


  const handleChangePrivacy = useCallback((vault: Vault) => {
    setShowManageVaultModal(false);
    // Aquí implementarás la lógica para cambiar privacidad
    console.log('Change privacy for vault:', vault);
  }, []);

  const handleChangePassword = useCallback((vault: Vault) => {
    setShowManageVaultModal(false);
    // Aquí implementarás la lógica para cambiar contraseña
    console.log('Change password for vault:', vault);
  }, []);

  const handleConfirmDeleteVault = useCallback(async (masterPassword: string, movePasswordsToVault?: number) => {
    if (!vault) return { success: false, message: 'No hay vault seleccionado' };

    try {
      const result = await vaultService.deleteVault(vault.id, masterPassword, movePasswordsToVault);
      
      if (result.success) {
        // Recargar vaults globalmente
        await reloadVaults();
        // Volver a la página anterior
        onBack();
        return { success: true, message: result.message };
      } else {
        return { success: false, message: result.error || 'Error al eliminar el vault' };
      }
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Error al eliminar el vault';
      return { success: false, message: errorMessage };
    }
  }, [vault, reloadVaults, onBack]);

  // Manejar desbloqueo del vault
  const handleUnlockVault = useCallback(async (vaultPassword: string) => {
  setUnlockVaultLoading(true);
  setUnlockVaultError('');
  
  try {
    const result = await vaultService.unlockVault(vaultId, vaultPassword);
    
    if (result.success) {
      markVaultAsUnlocked(vaultId);
      setShowUnlockVaultModal(false);
      
      // NUEVO: Si el unlock fue iniciado desde "Agregar Contraseña", abrir ese modal
      // Puedes usar un flag para rastrear esto
      return { success: true };
    } else {
      throw new Error(result.error || 'Contraseña incorrecta');
    }
  } catch (err) {
    const errorMessage = err instanceof Error ? err.message : 'Error al desbloquear el vault';
    setUnlockVaultError(errorMessage);
    throw new Error(errorMessage);
  } finally {
    setUnlockVaultLoading(false);
  }
}, [vaultId, markVaultAsUnlocked]);

  // Manejar desbloqueo de contraseña individual
  const handleUnlockPassword = useCallback((accountId: number) => {
    setSelectedAccount(accountId);
    setShowUnlockPasswordModal(true);
    setUnlockPasswordError('');
  }, []);

  const handleUnlockPasswordSubmit = useCallback(async (masterPassword: string) => {
    if (!selectedAccount) return;

    setUnlockPasswordLoading(true);
    setUnlockPasswordError('');
    
    try {
      const result = await passwordService.unlockPassword(selectedAccount, masterPassword);
      
      if (result.success && result.password) {
        // Actualizar la contraseña en el estado local
        setPasswords(prev => prev.map(acc => 
          acc.id === selectedAccount 
            ? { ...acc, decrypted_password: result.password }
            : acc
        ));
        setShowUnlockPasswordModal(false);
        setSelectedAccount(null);
      } else {
        throw new Error(result.error || 'Error al desbloquear la contraseña');
      }
    } catch (error) {
      setUnlockPasswordError('Contraseña maestra incorrecta');
    } finally {
      setUnlockPasswordLoading(false);
    }
  }, [selectedAccount]);

  // Otros handlers (editar, eliminar, agregar, copiar)
  const handleEdit = useCallback((accountId: number) => {
    setSelectedAccount(accountId);
    setShowEditModal(true);
  }, []);

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
      const result = await passwordService.deletePassword(selectedAccount, masterPassword);
      
      if (result.success) {
        // Eliminar la contraseña del estado local
        setPasswords(prev => prev.filter(acc => acc.id !== selectedAccount));
        setShowDeleteModal(false);
        setSelectedAccount(null);
        
        // Actualizar el contador en el vault
        if (vault) {
          setVault(prev => prev ? { ...prev, password_count: prev.password_count - 1 } : null);
        }
      } else {
        throw new Error(result.error || 'Error al eliminar la contraseña');
      }
    } catch (error) {
      setDeleteError('Error al eliminar la contraseña');
    } finally {
      setDeleteLoading(false);
    }
  }, [selectedAccount, vault]);

  const handleCopy = useCallback((password: string) => {
  navigator.clipboard.writeText(password).then(() => {
    setToastMessage("Contraseña copiada ✓");
    setTimeout(() => setToastMessage(null), 2000);
  });
}, []);

  const handleAddPassword = useCallback(() => {
  if (vault && vault.is_private && !isVaultUnlocked(vault.id)) {
    setShowUnlockVaultModal(true);
    return;
  }

  setShowAddModal(true);
  setAddError('');
  }, [vault, isVaultUnlocked]);

  const handleAddPasswordSubmit = useCallback(async (passwordData: AddPasswordData) => {
    setAddLoading(true);
    setAddError('');
    
    try {
      // Sólo el vault_id: si es privado, ya está desbloqueado (esta página no se muestra si no),
      // así que su VaultSubKey está en cryptoSession y el servidor tiene el marcador (paso 24).
      const dataWithVault: AddPasswordWithVaultData = {
        ...passwordData,
        vault_id: vault?.id || null,
      };

      const result = await passwordService.createAccount(dataWithVault);
      
      if (result.success) {
        // Recargar las contraseñas del vault
        setShowAddModal(false);

        await reloadPasswords();

        setToastMessage("Contraseña creada exitosamente ✓");
        setTimeout(() => setToastMessage(null), 3000);
        return { success: true };
      } else {
        throw new Error(result.error || 'Error al crear la contraseña');
      }
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Error al crear la contraseña';
      setAddError(errorMessage);
      return { success: false, error: errorMessage };
    } finally {
      setAddLoading(false);
    }
  },[vault, isVaultUnlocked, loadVaultData]);

  const handleEditSubmit = useCallback(async (
    accountId: number, 
    passwordData: EditPasswordData, 
    masterPassword?: string
  ) => {
    setEditLoading(true);
    
    try {
      const result = await passwordService.updatePassword(accountId, passwordData, masterPassword);
      
      if (result.success) {
        // Actualizar la contraseña en el estado local
        setPasswords(prev => prev.map(acc => 
          acc.id === accountId 
            ? { 
                ...acc, 
                website: passwordData.website || acc.website,
                username: passwordData.username || acc.username,
                encryption_algorithm: passwordData.algorithm || acc.encryption_algorithm,
                decrypted_password: passwordData.password ? undefined : acc.decrypted_password
              }
            : acc
        ));
        setShowEditModal(false);
        return { success: true };
      } else {
        throw new Error(result.error || 'Error al actualizar la contraseña');
      }
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Error al actualizar la contraseña';
      return { success: false, error: errorMessage };
    } finally {
      setEditLoading(false);
    }
  }, []);


  // Contraseñas filtradas
  const filteredPasswords = React.useMemo(() => {
    return passwords
      .filter(account => 
        account.website.toLowerCase().includes(searchTerm.toLowerCase()) ||
        account.username.toLowerCase().includes(searchTerm.toLowerCase())
      )
      .sort((a, b) => a[sortBy].localeCompare(b[sortBy]));
  }, [passwords, searchTerm, sortBy]);

  const selectedAccountData = passwords.find(acc => acc.id === selectedAccount) || null;

  // Estados de carga y error
  if (loading) {
    return (
      <div 
        className="min-h-screen flex items-center justify-center"
        style={{ backgroundColor: colors.background }}
      >
        <div className="text-center">
          <RefreshCw 
            className="w-8 h-8 animate-spin mx-auto mb-4" 
            style={{ color: colors.primary }} 
          />
          <p style={{ color: colors.textSecondary }}>Cargando vault...</p>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div 
        className="min-h-screen flex items-center justify-center"
        style={{ backgroundColor: colors.background }}
      >
        <div className="text-center">
          <p className="mb-4" style={{ color: colors.error }}>{error}</p>
          <button
            onClick={() => onBack()}
            className="px-4 py-2 rounded-lg text-white"
            style={{ backgroundColor: colors.primary }}
          >
            Volver
          </button>
        </div>
      </div>
    );
  }

  if (!vault) {
    return (
      <div 
        className="min-h-screen flex items-center justify-center"
        style={{ backgroundColor: colors.background }}
      >
        <p style={{ color: colors.textSecondary }}>Vault no encontrado</p>
      </div>
    );
  }

  const colorScheme = VAULT_COLORS[vault.color];

  return (
    <div className="min-h-screen p-6" style={{ backgroundColor: colors.background }}>
      {/* Header del vault */}
      <div className="mb-8">
        <div className="flex items-center justify-between mb-6">
          <button
            onClick={onBack}
            className="flex items-center space-x-2 px-3 py-2 rounded-lg border transition-colors"
            style={{
              backgroundColor: colors.surface,
              borderColor: colors.border,
              color: colors.textSecondary
            }}
          >
            <ArrowLeft className="w-4 h-4" />
            <span>Volver</span>
          </button>
          
          {isVaultUnlocked(vaultId) && (
            <button
              onClick={handleAddPassword}
              className="flex items-center space-x-2 px-4 py-2 rounded-lg text-white font-medium"
              style={{ backgroundColor: colors.primary }}
            >
              <Plus className="w-5 h-5" />
              <span>Agregar Contraseña</span>
            </button>
          )}
        </div>

        <div 
          className="p-6 rounded-xl border"
          style={{
            backgroundColor: colors.surface,
            borderColor: colors.border
          }}
        >
          <div className="button-group">
            <div 
              className={`w-16 h-16 rounded-xl flex items-center justify-center ${colorScheme.bg}`}
            >
              {vault.is_private ? (
                <Lock className={`w-8 h-8 ${colorScheme.icon}`} />
              ) : (
                <Folder className={`w-8 h-8 ${colorScheme.icon}`} />
              )}
            </div>

            <div className="flex-1">
              <h1 className="text-2xl font-bold mb-2" style={{ color: colors.textPrimary }}>
                {vault.name}
              </h1>
              {vault.description && (
                <p className="mb-3" style={{ color: colors.textSecondary }}>
                  {vault.description}
                </p>
              )}
              <div className="flex items-center space-x-4 text-sm" style={{ color: colors.textMuted }}>
                <span>{vault.password_count} contraseñas</span>
                <span>•</span>
                <span>{vault.is_private ? 'Vault privado' : 'Vault público'}</span>
                <span>•</span>
                <span>Creado {new Date(vault.created_at).toLocaleDateString()}</span>
              </div>
            </div>

            <div className="flex items-center gap-3">
              {/* Botón editar */}
              <button
                onClick={() => setShowManageVaultModal(true)}
                className="edit-btn"
                style={{
                  backgroundColor: colors.surface,
                  color: colors.textSecondary
                }}
                title="Gestionar vault"
              >
                <Settings className="w-5 h-5" />
              </button>

              {/* Botón eliminar */}
              <button
                onClick={() => setShowDeleteVaultModal(true)}
                className="delete-btn"
                style={{
                  backgroundColor: colors.surface,
                  color: colors.error
                }}
                title="Eliminar vault"
              >
                <Trash2 className="w-5 h-5" />
              </button>

              {/* Badge color vault */}
              <div 
                className={`px-3 py-1 rounded-full text-sm font-medium ${colorScheme.bg} ${colorScheme.text}`}
              >
                {vault.color.charAt(0).toUpperCase() + vault.color.slice(1)}
              </div>
            </div>
          </div>
        </div>


        {/* Barra de búsqueda y filtros (solo si el vault está desbloqueado) */}
        {isVaultUnlocked(vaultId) && (
          <div className="flex flex-col sm:flex-row gap-4 mt-6">
            <div className="flex-1 relative">
              <Search 
                className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5" 
                style={{ color: colors.textMuted }} 
              />
              <input
                type="text"
                placeholder="Buscar en este vault..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="w-full pl-10 pr-4 py-2 rounded-lg border focus:outline-none focus:ring-2"
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
        )}
      </div>

      {/* Contenido principal */}
      {!isVaultUnlocked(vaultId) ? (
        <div className="text-center py-12">
          <div className="mb-6">
            <div 
              className={`w-24 h-24 rounded-full flex items-center justify-center mx-auto ${colorScheme.bg}`}
            >
              <Lock className={`w-12 h-12 ${colorScheme.icon}`} />
            </div>
          </div>
          <h2 className="text-xl font-semibold mb-2" style={{ color: colors.textPrimary }}>
            Vault Bloqueado
          </h2>
          <p className="mb-6" style={{ color: colors.textSecondary }}>
            Este vault está protegido con contraseña. Desbloquéalo para ver las contraseñas.
          </p>
          <button
            onClick={() => setShowUnlockVaultModal(true)}
            className="px-6 py-3 rounded-lg text-white font-medium"
            style={{ backgroundColor: colors.primary }}
          >
            Desbloquear Vault
          </button>
        </div>
      ) : filteredPasswords.length === 0 ? (
        <div className="text-center py-12">
          {searchTerm ? (
            <div>
              <Search 
                className="w-16 h-16 mx-auto mb-4"
                style={{ color: colors.textMuted }}
              />
              <h2 className="text-xl font-semibold mb-2" style={{ color: colors.textPrimary }}>
                Sin resultados
              </h2>
              <p className="mb-6" style={{ color: colors.textSecondary }}>
                No se encontraron contraseñas que coincidan con "{searchTerm}"
              </p>
              <button
                onClick={() => setSearchTerm('')}
                className="px-4 py-2 rounded-lg border"
                style={{
                  backgroundColor: colors.surface,
                  borderColor: colors.border,
                  color: colors.textSecondary
                }}
              >
                Limpiar búsqueda
              </button>
            </div>
          ) : (
            <div>
              <Shield 
                className="w-16 h-16 mx-auto mb-4"
                style={{ color: colors.textMuted }}
              />
              <h2 className="text-xl font-semibold mb-2" style={{ color: colors.textPrimary }}>
                Este vault está vacío
              </h2>
              <p className="mb-6" style={{ color: colors.textSecondary }}>
                Agrega tu primera contraseña a este vault
              </p>
              <button
                onClick={handleAddPassword}
                className="px-6 py-3 rounded-lg text-white font-medium"
                style={{ backgroundColor: colors.primary }}
              >
                Agregar Primera Contraseña
              </button>
            </div>
          )}
        </div>
      ) : (
        <div className="password-cards-grid">
          {filteredPasswords.map((account) => (
            <VaultPasswordCard
              key={account.id}
              account={account}
              vault={vault}
              onUnlock={handleUnlockPassword}
              onEdit={handleEdit}
              onDelete={handleDelete}
              onCopy={handleCopy}
              isUnlocked={!!account.decrypted_password}
            />
          ))}
        </div>
      )}

      {/* Mensaje de copia */}
      {toastMessage && (
        <div className="fixed bottom-4 right-4 px-4 py-2 rounded-lg text-white z-40"
             style={{ backgroundColor: colors.success || colors.primary }}>
          {toastMessage}
        </div>
      )}

      {/* Modales */}
      
      {/* Modal para desbloquear vault */}
      {showUnlockVaultModal && (
        <UnlockVaultModal
          isOpen={showUnlockVaultModal}
          onClose={() => setShowUnlockVaultModal(false)}
          onSubmit={handleUnlockVault}
          vault={vault}
          loading={unlockVaultLoading}
        />
      )}

      {/* Modal para gestionar vault */}
      <ManageVaultModal
        isOpen={showManageVaultModal}
        onClose={() => setShowManageVaultModal(false)}
        vault={vault}
        onEdit={handleEditVault}
        onDelete={handleDeleteVault}
        onChangePrivacy={handleChangePrivacy}
        onChangePassword={handleChangePassword}
      />

      {/* Modal para eliminar vault */}
      <DeleteVaultModal
        isOpen={showDeleteVaultModal}
        onClose={() => setShowDeleteVaultModal(false)}
        onConfirm={handleConfirmDeleteVault}
        vault={vault}
        availableVaults={vaults.filter(v => v.id !== vault?.id)}
        loading={false}
      />

      {/* Modal para desbloquear contraseña individual */}
      <UnlockModal
        isOpen={showUnlockPasswordModal}
        onClose={() => {
          setShowUnlockPasswordModal(false);
          setSelectedAccount(null);
          setUnlockPasswordError('');
        }}
        onSubmit={handleUnlockPasswordSubmit}
        loading={unlockPasswordLoading}
        error={unlockPasswordError}
      />

      {/* Modal para eliminar contraseña */}
      <DeleteConfirmModal
        isOpen={showDeleteModal}
        onClose={() => {
          setShowDeleteModal(false);
          setSelectedAccount(null);
          setDeleteError('');
        }}
        onConfirm={handleDeleteConfirm}
        loading={deleteLoading}
        error={deleteError}
        accountName={
          selectedAccountData
            ? `${selectedAccountData.username} en ${selectedAccountData.website}`
            : "esta contraseña"
        }
      />

      {/* Modal para agregar contraseña */}
      <AddPasswordModal
        isOpen={showAddModal}
        onClose={() => {
          setShowAddModal(false);
          setAddError('');
        }}
        onSubmit={handleAddPasswordSubmit}
        loading={addLoading}
        preselectedVault={vault}
      />

      {/* Modal para editar contraseña */}
      <EditPasswordModal
        isOpen={showEditModal}
        onClose={() => {
          setShowEditModal(false);
          setSelectedAccount(null);
        }}
        onSubmit={handleEditSubmit}
        onRequestMasterPassword={(accountId, formData) => {
          // Lógica para solicitar contraseña maestra si es necesario
          console.log('Request master password for account:', accountId, formData);
        }}
        loading={editLoading}
        account={selectedAccountData}
      />
    </div>
  );
};