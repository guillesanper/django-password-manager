import React, { useState } from 'react';
import { Key, Lock, Shield, AlertCircle, Eye, EyeOff, CheckCircle, X } from 'lucide-react';
import { useUnifiedTheme } from '../theme/UnifiedThemeProvider';

interface MasterKeyModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSubmit: (masterKey: string) => Promise<{ success: boolean; error?: string }>;
  userName?: string;
}

export const MasterKeyModal: React.FC<MasterKeyModalProps> = ({
  isOpen,
  onClose,
  onSubmit,
  userName = 'Usuario'
}) => {
  const { colors } = useUnifiedTheme();
  const [masterKey, setMasterKey] = useState('');
  const [confirmMasterKey, setConfirmMasterKey] = useState('');
  const [showMasterKey, setShowMasterKey] = useState(false);
  const [showConfirmMasterKey, setShowConfirmMasterKey] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [step, setStep] = useState<'explanation' | 'setup'>('explanation');

  if (!isOpen) return null;

  // Validación de seguridad de la clave maestra
  const getKeyStrength = (key: string): { strength: number; label: string; color: string } => {
    if (key.length === 0) return { strength: 0, label: '', color: colors?.textMuted || '#6B7280' };
    if (key.length < 8) return { strength: 25, label: 'Muy débil', color: colors?.error || '#EF4444' };
    if (key.length < 12) return { strength: 50, label: 'Débil', color: colors?.warning || '#F59E0B' };
    if (key.length >= 12 && /(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])/.test(key)) {
      return { strength: 100, label: 'Muy fuerte', color: colors?.success || '#10B981' };
    }
    if (key.length >= 12 && /(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/.test(key)) {
      return { strength: 85, label: 'Fuerte', color: colors?.success || '#10B981' };
    }
    return { strength: 65, label: 'Moderada', color: colors?.primary || '#6366F1' };
  };

  const keyStrength = getKeyStrength(masterKey);

  const handleSubmit = async () => {
    setError('');

    // Validaciones
    if (!masterKey.trim()) {
      setError('La clave maestra es requerida');
      return;
    }

    if (masterKey.length < 12) {
      setError('La clave maestra debe tener al menos 12 caracteres');
      return;
    }

    if (masterKey !== confirmMasterKey) {
      setError('Las claves maestras no coinciden');
      return;
    }

    if (keyStrength.strength < 65) {
      setError('La clave maestra debe ser más segura. Usa mayúsculas, minúsculas, números y símbolos.');
      return;
    }

    setLoading(true);

    try {
      const result = await onSubmit(masterKey);
      if (result.success) {
        // Limpiar formulario y cerrar
        setMasterKey('');
        setConfirmMasterKey('');
        setStep('explanation');
        onClose();
      } else {
        setError(result.error || 'Error al configurar la clave maestra');
      }
    } catch (err) {
      setError('Error de conexión. Intenta de nuevo.');
    } finally {
      setLoading(false);
    }
  };

  const isFormValid = () => {
    return masterKey.length >= 12 && 
           masterKey === confirmMasterKey && 
           keyStrength.strength >= 65;
  };

  return (
    <div className="fixed inset-0 flex items-center justify-center p-4 z-50">
      {/* CAMBIO: Fondo con blur y backdrop */}
      <div 
        className="absolute inset-0"
        style={{
          backgroundColor: 'rgba(0, 0, 0, 0.4)',
          backdropFilter: 'blur(8px)',
          WebkitBackdropFilter: 'blur(8px)', // Safari support
        }}
        onClick={() => {
          // Solo permitir cerrar si ya tiene clave maestra o está en paso de explicación
          if (step === 'explanation') {
            onClose();
          }
        }}
      />
      
      {/* Modal content */}
      <div 
        className="relative max-w-md w-full rounded-2xl shadow-2xl border max-h-[90vh] overflow-y-auto"
        style={{ 
          backgroundColor: colors.surface, 
          borderColor: colors.border,
          boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.25)'
        }}
      >
        {step === 'explanation' ? (
          // Paso 1: Explicación
          <div className="p-8">
            {/* Header */}
            <div className="text-center mb-6">
              <div className="flex items-center justify-center mb-4">
                <div className="p-3 rounded-full bg-gradient-to-r from-indigo-500 to-purple-600">
                  <Shield className="w-8 h-8 text-white" />
                </div>
              </div>
              <h2 className="text-2xl font-bold mb-2" style={{ color: colors.textPrimary }}>
                ¡Bienvenido, {userName}! 🎉
              </h2>
              <p className="text-sm" style={{ color: colors.textSecondary }}>
                Configura tu clave maestra para proteger todas tus contraseñas
              </p>
            </div>

            {/* Explicación */}
            <div className="space-y-4 mb-8">
              <div 
                className="p-4 rounded-lg border-l-4"
                style={{ 
                  backgroundColor: `${colors.primary}10`,
                  borderColor: colors.primary
                }}
              >
                <div className="flex items-start">
                  <Key className="w-5 h-5 mr-3 mt-0.5" style={{ color: colors.primary }} />
                  <div>
                    <h4 className="font-semibold mb-1" style={{ color: colors.textPrimary }}>
                      ¿Qué es una clave maestra?
                    </h4>
                    <p className="text-sm" style={{ color: colors.textSecondary }}>
                      Es la única contraseña que necesitarás recordar. Protegerá todas tus otras contraseñas.
                    </p>
                  </div>
                </div>
              </div>

              <div className="space-y-3">
                <h4 className="font-medium flex items-center" style={{ color: colors.textPrimary }}>
                  <AlertCircle className="w-4 h-4 mr-2" style={{ color: colors.warning }} />
                  Características importantes:
                </h4>
                <div className="space-y-2 text-sm" style={{ color: colors.textSecondary }}>
                  <div className="flex items-center">
                    <CheckCircle className="w-4 h-4 mr-2" style={{ color: colors.success }} />
                    <span>Mínimo 12 caracteres</span>
                  </div>
                  <div className="flex items-center">
                    <CheckCircle className="w-4 h-4 mr-2" style={{ color: colors.success }} />
                    <span>Combina mayúsculas, minúsculas, números y símbolos</span>
                  </div>
                  <div className="flex items-center">
                    <CheckCircle className="w-4 h-4 mr-2" style={{ color: colors.success }} />
                    <span>Debe ser única y memorable para ti</span>
                  </div>
                  <div className="flex items-center">
                    <AlertCircle className="w-4 h-4 mr-2" style={{ color: colors.error }} />
                    <span className="font-medium">¡No la olvides! No puede ser recuperada.</span>
                  </div>
                </div>
              </div>
            </div>

            {/* Botones */}
            <div className="space-y-3">
              <button
                onClick={() => setStep('setup')}
                className="w-full py-3 px-4 rounded-lg font-semibold text-white transition-all duration-200 hover:scale-[1.02]"
                style={{ backgroundColor: colors.primary }}
              >
                Configurar Clave Maestra
              </button>
            </div>
          </div>
        ) : (
          // Paso 2: Configuración
          <div className="p-8">
            {/* Header */}
            <div className="flex items-center justify-between mb-6">
              <div>
                <h2 className="text-xl font-bold" style={{ color: colors.textPrimary }}>
                  Crear Clave Maestra
                </h2>
                <p className="text-sm" style={{ color: colors.textSecondary }}>
                  Esta clave protegerá todas tus contraseñas
                </p>
              </div>
              <button
                onClick={() => setStep('explanation')}
                className="p-2 rounded-lg transition-colors"
                style={{ 
                  backgroundColor: colors.surfaceHover,
                  color: colors.textMuted
                }}
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Error */}
            {error && (
              <div className="mb-4 p-3 rounded-lg border-l-4 bg-red-50 border-red-500">
                <div className="flex items-center">
                  <AlertCircle className="w-4 h-4 text-red-500 mr-2" />
                  <p className="text-sm text-red-700">{error}</p>
                </div>
              </div>
            )}

            <div className="space-y-4">
              {/* Campo de clave maestra */}
              <div>
                <label className="block text-sm font-medium mb-2" style={{ color: colors.textPrimary }}>
                  Clave Maestra <span style={{ color: colors.error }}>*</span>
                </label>
                <div className="relative">
                  <Lock className="absolute left-3 top-3 w-5 h-5" style={{ color: colors.textMuted }} />
                  <input
                    type={showMasterKey ? 'text' : 'password'}
                    value={masterKey}
                    onChange={(e) => {
                      setMasterKey(e.target.value);
                      setError('');
                    }}
                    placeholder="Crea una clave maestra muy segura"
                    className="w-full pl-10 pr-12 py-3 rounded-lg border transition-all duration-200 focus:outline-none focus:ring-2 focus:border-transparent"
                    style={{
                      backgroundColor: colors.surface,
                      borderColor: error ? colors.error : colors.border,
                      color: colors.textPrimary
                    }}
                  />
                  <button
                    type="button"
                    onClick={() => setShowMasterKey(!showMasterKey)}
                    className="absolute right-3 top-3 p-1 rounded-md transition-colors"
                    style={{ color: colors.textMuted }}
                  >
                    {showMasterKey ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
                  </button>
                </div>

                {/* Indicador de seguridad */}
                {masterKey && (
                  <div className="mt-2 space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="text-xs" style={{ color: colors.textMuted }}>
                        Seguridad de la clave
                      </span>
                      <span 
                        className="text-xs font-medium" 
                        style={{ color: keyStrength.color }}
                      >
                        {keyStrength.label}
                      </span>
                    </div>
                    <div className="w-full bg-gray-200 rounded-full h-1.5">
                      <div
                        className="h-1.5 rounded-full transition-all duration-300"
                        style={{
                          width: `${keyStrength.strength}%`,
                          backgroundColor: keyStrength.color
                        }}
                      ></div>
                    </div>
                    
                    {/* Requisitos */}
                    <div className="text-xs space-y-1 mt-3">
                      <p className={`transition-colors flex items-center gap-1 ${
                        masterKey.length >= 12 ? 'text-green-600' : 'text-gray-400'
                      }`}>
                        <span>{masterKey.length >= 12 ? '✓' : '○'}</span> Al menos 12 caracteres
                      </p>
                      <p className={`transition-colors flex items-center gap-1 ${
                        /(?=.*[a-z])(?=.*[A-Z])/.test(masterKey) ? 'text-green-600' : 'text-gray-400'
                      }`}>
                        <span>{/(?=.*[a-z])(?=.*[A-Z])/.test(masterKey) ? '✓' : '○'}</span> Mayúsculas y minúsculas
                      </p>
                      <p className={`transition-colors flex items-center gap-1 ${
                        /(?=.*\d)/.test(masterKey) ? 'text-green-600' : 'text-gray-400'
                      }`}>
                        <span>{/(?=.*\d)/.test(masterKey) ? '✓' : '○'}</span> Al menos un número
                      </p>
                      <p className={`transition-colors flex items-center gap-1 ${
                        /(?=.*[@$!%*?&])/.test(masterKey) ? 'text-green-600' : 'text-gray-400'
                      }`}>
                        <span>{/(?=.*[@$!%*?&])/.test(masterKey) ? '✓' : '○'}</span> Al menos un símbolo (@$!%*?&)
                      </p>
                    </div>
                  </div>
                )}
              </div>

              {/* Confirmar clave maestra */}
              <div>
                <label className="block text-sm font-medium mb-2" style={{ color: colors.textPrimary }}>
                  Confirmar Clave Maestra <span style={{ color: colors.error }}>*</span>
                </label>
                <div className="relative">
                  <Lock className="absolute left-3 top-3 w-5 h-5" style={{ color: colors.textMuted }} />
                  <input
                    type={showConfirmMasterKey ? 'text' : 'password'}
                    value={confirmMasterKey}
                    onChange={(e) => {
                      setConfirmMasterKey(e.target.value);
                      setError('');
                    }}
                    placeholder="Confirma tu clave maestra"
                    className="w-full pl-10 pr-12 py-3 rounded-lg border transition-all duration-200 focus:outline-none focus:ring-2 focus:border-transparent"
                    style={{
                      backgroundColor: colors.surface,
                      borderColor: error || (confirmMasterKey && masterKey !== confirmMasterKey) ? colors.error : colors.border,
                      color: colors.textPrimary
                    }}
                  />
                  <button
                    type="button"
                    onClick={() => setShowConfirmMasterKey(!showConfirmMasterKey)}
                    className="absolute right-3 top-3 p-1 rounded-md transition-colors"
                    style={{ color: colors.textMuted }}
                  >
                    {showConfirmMasterKey ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
                  </button>
                </div>
                
                {confirmMasterKey && masterKey !== confirmMasterKey && (
                  <p className="text-xs mt-1" style={{ color: colors.error }}>
                    Las claves maestras no coinciden
                  </p>
                )}
                
                {confirmMasterKey && masterKey === confirmMasterKey && masterKey && (
                  <p className="text-xs mt-1" style={{ color: colors.success }}>
                    ✓ Las claves maestras coinciden
                  </p>
                )}
              </div>

              {/* Advertencia */}
              <div 
                className="p-3 rounded-lg border"
                style={{ 
                  backgroundColor: `${colors.warning}10`,
                  borderColor: colors.warning
                }}
              >
                <div className="flex items-start">
                  <AlertCircle className="w-4 h-4 mr-2 mt-0.5" style={{ color: colors.warning }} />
                  <div className="text-xs" style={{ color: colors.textSecondary }}>
                    <strong>¡Importante!</strong> Si olvidas tu clave maestra, no podrás acceder a tus contraseñas. 
                    Guárdala en un lugar seguro.
                  </div>
                </div>
              </div>

              {/* Botones */}
              <div className="flex space-x-3 pt-4">
                <button
                  onClick={() => setStep('explanation')}
                  disabled={loading}
                  className="flex-1 py-3 px-4 rounded-lg font-medium border transition-all duration-200"
                  style={{
                    borderColor: colors.border,
                    color: colors.textSecondary,
                    backgroundColor: 'transparent'
                  }}
                >
                  Atrás
                </button>
                <button
                  onClick={handleSubmit}
                  disabled={loading || !isFormValid()}
                  className="flex-1 py-3 px-4 rounded-lg font-semibold text-white transition-all duration-200 hover:scale-[1.02] disabled:opacity-50 disabled:cursor-not-allowed"
                  style={{ backgroundColor: colors.primary }}
                >
                  {loading ? (
                    <span className="flex items-center justify-center">
                      <div className="animate-spin rounded-full h-4 w-4 border-2 border-transparent border-t-current mr-2"></div>
                      Configurando...
                    </span>
                  ) : (
                    'Configurar Clave Maestra'
                  )}
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};