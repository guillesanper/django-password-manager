// components/AuthErrorProvider.tsx
import React, { createContext, useContext, useState, useCallback, useEffect, useRef } from 'react';
import type { ReactNode } from 'react';
import type { FormData } from '../AuthComponents';

interface AuthErrorContextType {
  // Estados de error
  loginErrors: Partial<FormData>;
  loginApiError: string;
  registerErrors: Partial<FormData>;
  registerApiError: string;
  
  // Métodos para login
  setLoginErrors: (errors: Partial<FormData>) => void;
  setLoginApiError: (error: string) => void;
  clearLoginErrors: () => void;
  
  // Métodos para register
  setRegisterErrors: (errors: Partial<FormData>) => void;
  setRegisterApiError: (error: string) => void;
  clearRegisterErrors: () => void;
  
  // Métodos generales
  clearAllErrors: () => void;
  
  // Helpers para validación en tiempo real
  clearLoginFieldError: (field: keyof FormData) => void;
  clearRegisterFieldError: (field: keyof FormData) => void;
}

const AuthErrorContext = createContext<AuthErrorContextType | undefined>(undefined);

export const useAuthErrors = (): AuthErrorContextType => {
  const context = useContext(AuthErrorContext);
  if (!context) {
    throw new Error('useAuthErrors debe ser usado dentro de un AuthErrorProvider');
  }
  return context;
};

interface AuthErrorProviderProps {
  children: ReactNode;
}

export const AuthErrorProvider: React.FC<AuthErrorProviderProps> = ({ children }) => {
  // Estados separados para login y register
  const [loginErrors, setLoginErrorsState] = useState<Partial<FormData>>({});
  const [loginApiError, setLoginApiErrorState] = useState<string>('');
  const [registerErrors, setRegisterErrorsState] = useState<Partial<FormData>>({});
  const [registerApiError, setRegisterApiErrorState] = useState<string>('');

  // Refs para timeouts de limpieza automática
  const loginTimeoutRef = useRef<NodeJS.Timeout | null>(null);
  const registerTimeoutRef = useRef<NodeJS.Timeout | null>(null);

  // Función para limpiar timeouts
  const clearTimeouts = useCallback(() => {
    if (loginTimeoutRef.current) {
      clearTimeout(loginTimeoutRef.current);
      loginTimeoutRef.current = null;
    }
    if (registerTimeoutRef.current) {
      clearTimeout(registerTimeoutRef.current);
      registerTimeoutRef.current = null;
    }
  }, []);

  // Cleanup al desmontar
  useEffect(() => {
    return clearTimeouts;
  }, [clearTimeouts]);

  // Métodos para login
  const setLoginErrors = useCallback((errors: Partial<FormData>) => {
    setLoginErrorsState(errors);
    
    // Auto-limpiar errores después de 30 segundos si no son críticos
    if (Object.keys(errors).length > 0) {
      if (loginTimeoutRef.current) {
        clearTimeout(loginTimeoutRef.current);
      }
      
      loginTimeoutRef.current = setTimeout(() => {
        setLoginErrorsState({});
      }, 30000); // 30 segundos
    }
  }, []);

  const setLoginApiError = useCallback((error: string) => {
    setLoginApiErrorState(error);
    
    // Auto-limpiar apiError después de 45 segundos para errores del sistema
    if (error) {
      if (loginTimeoutRef.current) {
        clearTimeout(loginTimeoutRef.current);
      }
      
      loginTimeoutRef.current = setTimeout(() => {
        setLoginApiErrorState('');
      }, 45000); // 45 segundos para errores críticos
    }
  }, []);

  const clearLoginErrors = useCallback(() => {
    setLoginErrorsState({});
    setLoginApiErrorState('');
    if (loginTimeoutRef.current) {
      clearTimeout(loginTimeoutRef.current);
      loginTimeoutRef.current = null;
    }
  }, []);

  const clearLoginFieldError = useCallback((field: keyof FormData) => {
    setLoginErrorsState(prev => {
      const newErrors = { ...prev };
      delete newErrors[field];
      return newErrors;
    });
    
    // También limpiar apiError si está relacionado con este campo
    setLoginApiErrorState(prev => {
      if (!prev) return prev;
      
      const lowerApiError = prev.toLowerCase();
      const fieldRelated = (field === 'email' && (lowerApiError.includes('email') || lowerApiError.includes('correo'))) ||
                          (field === 'password' && (lowerApiError.includes('contraseña') || lowerApiError.includes('password')));
      
      return fieldRelated ? '' : prev;
    });
  }, []);

  // Métodos para register
  const setRegisterErrors = useCallback((errors: Partial<FormData>) => {
    setRegisterErrorsState(errors);
    
    // Auto-limpiar errores después de 30 segundos
    if (Object.keys(errors).length > 0) {
      if (registerTimeoutRef.current) {
        clearTimeout(registerTimeoutRef.current);
      }
      
      registerTimeoutRef.current = setTimeout(() => {
        setRegisterErrorsState({});
      }, 30000);
    }
  }, []);

  const setRegisterApiError = useCallback((error: string) => {
    setRegisterApiErrorState(error);
    
    // Auto-limpiar apiError después de 45 segundos
    if (error) {
      if (registerTimeoutRef.current) {
        clearTimeout(registerTimeoutRef.current);
      }
      
      registerTimeoutRef.current = setTimeout(() => {
        setRegisterApiErrorState('');
      }, 45000);
    }
  }, []);

  const clearRegisterErrors = useCallback(() => {
    setRegisterErrorsState({});
    setRegisterApiErrorState('');
    if (registerTimeoutRef.current) {
      clearTimeout(registerTimeoutRef.current);
      registerTimeoutRef.current = null;
    }
  }, []);

  const clearRegisterFieldError = useCallback((field: keyof FormData) => {
    setRegisterErrorsState(prev => {
      const newErrors = { ...prev };
      delete newErrors[field];
      return newErrors;
    });
    
    // También limpiar apiError si está relacionado con este campo
    setRegisterApiErrorState(prev => {
      if (!prev) return prev;
      
      const lowerApiError = prev.toLowerCase();
      const fieldRelated = (field === 'email' && (lowerApiError.includes('email') || lowerApiError.includes('correo'))) ||
                          (field === 'password' && (lowerApiError.includes('contraseña') || lowerApiError.includes('password'))) ||
                          (field === 'firstName' && lowerApiError.includes('nombre')) ||
                          (field === 'lastName' && lowerApiError.includes('apellido'));
      
      return fieldRelated ? '' : prev;
    });
  }, []);

  // Método para limpiar todos los errores
  const clearAllErrors = useCallback(() => {
    setLoginErrorsState({});
    setLoginApiErrorState('');
    setRegisterErrorsState({});
    setRegisterApiErrorState('');
    clearTimeouts();
  }, [clearTimeouts]);

  const value: AuthErrorContextType = {
    // Estados
    loginErrors,
    loginApiError,
    registerErrors,
    registerApiError,
    
    // Métodos para login
    setLoginErrors,
    setLoginApiError,
    clearLoginErrors,
    clearLoginFieldError,
    
    // Métodos para register
    setRegisterErrors,
    setRegisterApiError,
    clearRegisterErrors,
    clearRegisterFieldError,
    
    // Método general
    clearAllErrors,
  };

  return (
    <AuthErrorContext.Provider value={value}>
      {children}
    </AuthErrorContext.Provider>
  );
};

// Hook especializado para login con lógica de clasificación de errores
export const useLoginErrorHandler = () => {
  const { 
    loginErrors, 
    loginApiError, 
    setLoginErrors, 
    setLoginApiError, 
    clearLoginErrors,
    clearLoginFieldError 
  } = useAuthErrors();

  const classifyAndSetError = useCallback((errorMessage: string) => {
    const lowerErrorMessage = errorMessage.toLowerCase();
    
    // Clasificar el tipo de error
    if (lowerErrorMessage.includes('email o contraseña') || 
        lowerErrorMessage.includes('credenciales') ||
        lowerErrorMessage.includes('incorrectos')) {
      
      // Error de credenciales - solo apiError para no dar pistas específicas
      setLoginApiError(errorMessage);
      
    } else if (lowerErrorMessage.includes('email') && 
               !lowerErrorMessage.includes('contraseña') &&
               (lowerErrorMessage.includes('no existe') || 
                lowerErrorMessage.includes('no encontrado') ||
                lowerErrorMessage.includes('inválido'))) {
      
      // Error específico del email
      setLoginErrors({ email: errorMessage });
      
    } else if (lowerErrorMessage.includes('contraseña') && 
               !lowerErrorMessage.includes('email') &&
               (lowerErrorMessage.includes('incorrecta') ||
                lowerErrorMessage.includes('inválida'))) {
      
      // Error específico de la contraseña
      setLoginErrors({ password: errorMessage });
      
    } else if (lowerErrorMessage.includes('intentos') || 
               lowerErrorMessage.includes('bloqueado') ||
               lowerErrorMessage.includes('minutos') ||
               lowerErrorMessage.includes('temporalmente') ||
               lowerErrorMessage.includes('many')) {
      
      // Rate limiting / cuenta bloqueada - solo apiError
      setLoginApiError(errorMessage);
      
    } else if (lowerErrorMessage.includes('servidor') ||
               lowerErrorMessage.includes('mantenimiento') ||
               lowerErrorMessage.includes('disponible')) {
      
      // Errores del servidor - solo apiError
      setLoginApiError(errorMessage);
      
    } else {
      // Error genérico - mejor UX sin dar pistas específicas
      setLoginApiError('Error de autenticación. Verifica tus credenciales.');
    }
  }, [setLoginErrors, setLoginApiError]);

  // NUEVA: Función que se debe llamar desde el componente cuando cambie un input
  const handleFieldChange = useCallback((field: keyof FormData, value: string) => {
    // Limpiar errores cuando el usuario empieza a corregir el campo
    if (loginErrors[field]) {
      if (field === 'email') {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (emailRegex.test(value.trim())) {
          clearLoginFieldError(field);
        }
      } else if (field === 'password') {
        if (value.length >= 6) {
          clearLoginFieldError(field);
        }
      }
    }
    
    // Auto-limpiar apiError si el usuario está corrigiendo un campo relacionado
    if (loginApiError) {
      const lowerApiError = loginApiError.toLowerCase();
      
      if (field === 'email' && value.trim() && 
          /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value.trim()) &&
          (lowerApiError.includes('email') || 
           lowerApiError.includes('correo'))) {
        setLoginApiError('');
      }
      
      if (field === 'password' && value.length >= 6 &&
          (lowerApiError.includes('contraseña') || 
           lowerApiError.includes('password'))) {
        setLoginApiError('');
      }
    }
  }, [loginErrors, loginApiError, clearLoginFieldError, setLoginApiError]);

  // Función de validación para el formulario
  const validateForm = useCallback((formData: FormData): { isValid: boolean; errors: Partial<FormData> } => {
    const newErrors: Partial<FormData> = {};

    if (!formData.email) {
      newErrors.email = 'El email es requerido';
    } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(formData.email.trim())) {
      newErrors.email = 'El email no es válido';
    }

    if (!formData.password) {
      newErrors.password = 'La contraseña es requerida';
    } else if (formData.password.length < 6) {
      newErrors.password = 'La contraseña debe tener al menos 6 caracteres';
    }

    const isValid = Object.keys(newErrors).length === 0;
    return { isValid, errors: newErrors };
  }, []);

  return {
    loginErrors,
    loginApiError,
    clearLoginErrors,
    classifyAndSetError,
    handleFieldChange, // NUEVA función que se debe usar en los onChange
    validateForm,
    setLoginErrors,
  };
};

// Hook especializado para register con validación completa
export const useRegisterErrorHandler = () => {
  const { 
    registerErrors, 
    registerApiError, 
    setRegisterErrors, 
    setRegisterApiError, 
    clearRegisterErrors,
    clearRegisterFieldError 
  } = useAuthErrors();

  const classifyAndSetError = useCallback((errorMessage: string) => {
    const lowerErrorMessage = errorMessage.toLowerCase();
    
    // Clasificar errores específicos de registro
    if (lowerErrorMessage.includes('email') && 
        (lowerErrorMessage.includes('existe') || 
         lowerErrorMessage.includes('already') || 
         lowerErrorMessage.includes('ya registrado') ||
         lowerErrorMessage.includes('correo'))) {
      setRegisterErrors({ email: errorMessage });
      
    } else if (lowerErrorMessage.includes('contraseña') || 
               lowerErrorMessage.includes('password')) {
      setRegisterErrors({ password: errorMessage });
      
    } else if (lowerErrorMessage.includes('nombre') ||
               lowerErrorMessage.includes('first_name')) {
      setRegisterErrors({ firstName: errorMessage });
      
    } else if (lowerErrorMessage.includes('apellido') ||
               lowerErrorMessage.includes('last_name')) {
      setRegisterErrors({ lastName: errorMessage });
      
    } else if (lowerErrorMessage.includes('confirmar') ||
               lowerErrorMessage.includes('confirm')) {
      setRegisterErrors({ confirmPassword: errorMessage });
      
    } else {
      // Error general del servidor, rate limiting, etc.
      setRegisterApiError(errorMessage);
    }
  }, [setRegisterErrors, setRegisterApiError]);

  // NUEVA: Función que se debe llamar desde el componente cuando cambie un input
  const handleFieldChange = useCallback((field: keyof FormData, value: string) => {
    // Limpiar error específico del campo cuando el usuario lo corrige
    if (registerErrors[field]) {
      let shouldClear = false;
      
      switch (field) {
        case 'email':
          shouldClear = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value.trim());
          break;
        case 'password':
          // Validación más estricta para el registro (12 caracteres mínimo)
          shouldClear = value.length >= 12 && 
                       /(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/.test(value);
          break;
        case 'confirmPassword':
          shouldClear = value.length >= 6;
          break;
        case 'firstName':
        case 'lastName':
          shouldClear = value.trim().length >= 2 && 
                       /^[a-zA-ZÀ-ÿ\s]+$/.test(value.trim());
          break;
      }
      
      if (shouldClear) {
        clearRegisterFieldError(field);
      }
    }
    
    // Limpiar apiError si está relacionado con el campo específico
    if (registerApiError) {
      const lowerApiError = registerApiError.toLowerCase();
      
      if ((field === 'email' && value.trim() && 
           /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value.trim()) &&
           (lowerApiError.includes('email') || lowerApiError.includes('correo'))) ||
          
          (field === 'firstName' && value.trim().length >= 2 && 
           lowerApiError.includes('nombre')) ||
           
          (field === 'lastName' && value.trim().length >= 2 && 
           lowerApiError.includes('apellido'))) {
        setRegisterApiError('');
      }
    }
  }, [registerErrors, registerApiError, clearRegisterFieldError, setRegisterApiError]);

  // Validación del formulario completo
  const validateForm = useCallback((formData: FormData): { isValid: boolean; errors: Partial<FormData> } => {
    const newErrors: Partial<FormData> = {};

    // Validación de nombre
    if (!formData.firstName?.trim()) {
      newErrors.firstName = 'El nombre es requerido';
    } else if (formData.firstName.trim().length < 2) {
      newErrors.firstName = 'El nombre debe tener al menos 2 caracteres';
    } else if (!/^[a-zA-ZÀ-ÿ\s]+$/.test(formData.firstName.trim())) {
      newErrors.firstName = 'El nombre solo puede contener letras';
    }

    // Validación de apellido
    if (!formData.lastName?.trim()) {
      newErrors.lastName = 'El apellido es requerido';
    } else if (formData.lastName.trim().length < 2) {
      newErrors.lastName = 'El apellido debe tener al menos 2 caracteres';
    } else if (!/^[a-zA-ZÀ-ÿ\s]+$/.test(formData.lastName.trim())) {
      newErrors.lastName = 'El apellido solo puede contener letras';
    }

    // Validación de email más estricta
    if (!formData.email?.trim()) {
      newErrors.email = 'El email es requerido';
    } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(formData.email.trim())) {
      newErrors.email = 'El email no es válido';
    }

    // Validación de contraseña más robusta
    if (!formData.password) {
      newErrors.password = 'La contraseña es requerida';
    } else if (formData.password.length < 12) {
      newErrors.password = 'La contraseña debe tener al menos 12 caracteres';
    } else if (!/(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?`~])/.test(formData.password)) {
      newErrors.password = 'La contraseña debe contener al menos una mayúscula, una minúscula, un número y un símbolo';
    }

    // Validación de confirmación de contraseña
    if (!formData.confirmPassword) {
      newErrors.confirmPassword = 'Confirma tu contraseña';
    } else if (formData.password !== formData.confirmPassword) {
      newErrors.confirmPassword = 'Las contraseñas no coinciden';
    }

    const isValid = Object.keys(newErrors).length === 0;
    return { isValid, errors: newErrors };
  }, []);

  return {
    registerErrors,
    registerApiError,
    clearRegisterErrors,
    classifyAndSetError,
    handleFieldChange, // NUEVA función que se debe usar en los onChange
    validateForm,
    setRegisterErrors,
  };
};