// components/account/hooks/usePasswordAccounts.ts
import { useState, useEffect, useCallback } from 'react';
import { type PasswordAccount } from '../account/AccountCard';
import { type AddPasswordWithVaultData } from '../account/AddPasswordModal';
import { passwordService } from '../../services/passwordService';

export const usePasswordAccounts = (vaultFilter?: string | number | null) => {
  const [accounts, setAccounts] = useState<PasswordAccount[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const loadAccounts = useCallback(async () => {
    setLoading(true);
    setError(null);
    
    try {
      console.log('🔄 Loading accounts with vault filter:', vaultFilter);
      
      let accountsData: PasswordAccount[];
      
      if (vaultFilter === 'all' || vaultFilter === undefined) {
        // Load all accounts
        accountsData = await passwordService.getAccountsWithVaults();
      } else if (vaultFilter === 'unvaulted') {
        // Load only accounts without vault
        accountsData = await passwordService.getAccountsWithVaults('unvaulted');
      } else {
        // Load accounts for specific vault
        accountsData = await passwordService.getAccountsWithVaults(vaultFilter);
      }
      
      console.log('✅ Loaded accounts:', accountsData.length, 'accounts');
      setAccounts(accountsData);
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Error al cargar las contraseñas';
      setError(errorMessage);
      console.error('Error loading accounts:', err);
    } finally {
      setLoading(false);
    }
  }, [vaultFilter]);

  useEffect(() => {
    loadAccounts();
  }, [loadAccounts]);

  const unlockAccount = useCallback(async (accountId: number, masterPassword: string) => {
    try {
      const result = await passwordService.unlockPassword(accountId, masterPassword);
      
      if (result.success && result.password) {
        setAccounts(prev => prev.map(acc => 
          acc.id === accountId 
            ? { ...acc, decrypted_password: result.password }
            : acc
        ));
        return { success: true };
      } else {
        throw new Error(result.error || 'Error al desbloquear la contraseña');
      }
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Error al desbloquear la contraseña';
      console.error('Error unlocking account:', err);
      throw new Error(errorMessage);
    }
  }, []);

  const deleteAccount = useCallback(async (accountId: number) => {
    try {
      const result = await passwordService.deletePassword(accountId);
      
      if (result.success) {
        setAccounts(prev => prev.filter(acc => acc.id !== accountId));
        return { success: true, message: result.message };
      } else {
        throw new Error(result.error || 'Error al eliminar la contraseña');
      }
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Error al eliminar la contraseña';
      console.error('Error deleting account:', err);
      throw new Error(errorMessage);
    }
  }, []);

  const updateAccount = useCallback(async (
    accountId: number, 
    updates: Partial<AddPasswordWithVaultData>,
    masterPassword?: string
  ) => {
    try {
      const result = await passwordService.updatePassword(accountId, updates, masterPassword);
      
      if (result.success) {
        setAccounts(prev => prev.map(acc => 
          acc.id === accountId 
            ? { 
                ...acc, 
                website: updates.website || acc.website,
                username: updates.username || acc.username,
                encryption_algorithm: updates.algorithm || acc.encryption_algorithm,
                decrypted_password: updates.password ? undefined : acc.decrypted_password
              }
            : acc
        ));
        return { success: true, message: result.message };
      } else {
        throw new Error(result.error || 'Error al actualizar la contraseña');
      }
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Error al actualizar la contraseña';
      console.error('Error updating account:', err);
      throw new Error(errorMessage);
    }
  }, []);

  const createAccount = useCallback(async (newAccount: AddPasswordWithVaultData) => {
    try {
      console.log('Creating account with vault data:', newAccount);
      
      const result = await passwordService.createAccount(newAccount);
      
      if (result.success) {
        // Reload accounts to get the new account with its generated ID
        await loadAccounts();
        return { success: true, message: result.message };
      } else {
        throw new Error(result.error || 'Error al crear la contraseña');
      }
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Error al crear la contraseña';
      console.error('Error creating account:', err);
      throw new Error(errorMessage);
    }
  }, [loadAccounts]);

  const unlockAllAccounts = useCallback(async (masterPassword: string) => {
    try {
      const result = await passwordService.unlockAllPasswords(masterPassword);
      
      if (result.success && result.accounts) {
        setAccounts(prev => prev.map(acc => {
          const unlockedAccount = result.accounts!.find(unlocked => unlocked.id === acc.id);
          return unlockedAccount 
            ? { ...acc, decrypted_password: unlockedAccount.decrypted_password }
            : acc;
        }));
        return { success: true, count: result.accounts.length };
      } else {
        throw new Error(result.error || 'Error al desbloquear las contraseñas');
      }
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Error al desbloquear las contraseñas';
      console.error('Error unlocking all accounts:', err);
      throw new Error(errorMessage);
    }
  }, []);

  const generatePasswords = useCallback(async (
    count: number = 5,
    length: number = 20,
    useSpecial: boolean = true,
    useNumbers: boolean = true
  ) => {
    try {
      const result = await passwordService.generatePasswords(count, length, useSpecial, useNumbers);
      
      if (result.success && result.passwords) {
        return result.passwords;
      } else {
        throw new Error(result.error || 'Error al generar contraseñas');
      }
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Error al generar contraseñas';
      console.error('Error generating passwords:', err);
      throw new Error(errorMessage);
    }
  }, []);

  const movePasswordToVault = useCallback(async (
    passwordId: number, 
    vaultId: number | null, 
    vaultPassword?: string
  ) => {
    try {
      const result = await passwordService.movePasswordToVault(passwordId, vaultId, vaultPassword);
      
      if (result.success) {
        await loadAccounts(); // Reload to reflect changes
        return { success: true, message: result.message };
      } else {
        throw new Error(result.error || 'Error al mover la contraseña');
      }
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Error al mover la contraseña';
      console.error('Error moving password to vault:', err);
      throw new Error(errorMessage);
    }
  }, [loadAccounts]);

  const batchMovePasswords = useCallback(async (
    passwordIds: number[], 
    destinationVaultId: number | null, 
    vaultPassword?: string
  ) => {
    try {
      const result = await passwordService.batchMovePasswords(passwordIds, destinationVaultId, vaultPassword);
      
      if (result.success) {
        await loadAccounts(); // Reload to reflect changes
        return { success: true, message: result.message };
      } else {
        throw new Error(result.error || 'Error al mover las contraseñas');
      }
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Error al mover las contraseñas';
      console.error('Error batch moving passwords:', err);
      throw new Error(errorMessage);
    }
  }, [loadAccounts]);

  const batchDeletePasswords = useCallback(async (
    passwordIds: number[], 
    masterPassword: string
  ) => {
    try {
      const result = await passwordService.batchDeletePasswords(passwordIds, masterPassword);
      
      if (result.success) {
        await loadAccounts(); // Reload to reflect changes
        return { success: true, message: result.message };
      } else {
        throw new Error(result.error || 'Error al eliminar las contraseñas');
      }
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Error al eliminar las contraseñas';
      console.error('Error batch deleting passwords:', err);
      throw new Error(errorMessage);
    }
  }, [loadAccounts]);

  const clearDecryptedPasswords = useCallback(() => {
    setAccounts(prev => prev.map(acc => ({
      ...acc,
      decrypted_password: undefined
    })));
  }, []);

  const hasUnlockedPasswords = useCallback(() => {
    return accounts.some(acc => acc.decrypted_password !== undefined);
  }, [accounts]);

  return {
    accounts,
    loading,
    error,
    unlockAccount,
    deleteAccount,
    updateAccount,
    createAccount,
    unlockAllAccounts,
    generatePasswords,
    movePasswordToVault,  
    batchMovePasswords,   
    batchDeletePasswords,
    reloadAccounts: loadAccounts,
    clearDecryptedPasswords,
    hasUnlockedPasswords
  };
};