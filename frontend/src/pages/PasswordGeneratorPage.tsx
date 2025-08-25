// pages/PasswordGeneratorPage.tsx
import React, { useState, useCallback, useEffect } from 'react';
import { 
  RefreshCw, 
  Copy, 
  Check, 
  Settings, 
  Key, 
  Shield, 
  Zap,
  Lock,
  Download,
  Save,
  Plus
} from 'lucide-react';
import { useUnifiedTheme } from '../theme/UnifiedThemeProvider';
import { AddPasswordModal, type AddPasswordData } from '../components/account/AddPasswordModal';
import { usePasswordAccounts } from '../components/account/hooks/usePasswordAccounts';

interface PasswordGeneratorPageProps {
  setCurrentPage?: (page: string) => void;
}

interface PasswordSettings {
  length: number;
  includeUppercase: boolean;
  includeLowercase: boolean;
  includeNumbers: boolean;
  includeSymbols: boolean;
  excludeSimilar: boolean;
  excludeAmbiguous: boolean;
}

interface GeneratedPassword {
  id: string;
  password: string;
  strength: 'weak' | 'medium' | 'strong' | 'very-strong' | 'extremely-strong';
  score: number;
  entropy: number;
  copied: boolean;
  saved: boolean;
}

export const PasswordGeneratorPage: React.FC<PasswordGeneratorPageProps> = ({ setCurrentPage }) => {
  const { colors } = useUnifiedTheme();
  const { createAccount } = usePasswordAccounts();
  
  // Settings state
  const [settings, setSettings] = useState<PasswordSettings>({
    length: 16,
    includeUppercase: true,
    includeLowercase: true,
    includeNumbers: true,
    includeSymbols: true,
    excludeSimilar: false,
    excludeAmbiguous: false
  });

  // Generated passwords state
  const [passwords, setPasswords] = useState<GeneratedPassword[]>([]);
  const [generating, setGenerating] = useState(false);
  
  // Modal states
  const [showAddModal, setShowAddModal] = useState(false);
  const [passwordToSave, setPasswordToSave] = useState<string>('');

  // Character sets
  const charSets = {
    uppercase: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
    lowercase: 'abcdefghijklmnopqrstuvwxyz',
    numbers: '0123456789',
    symbols: '!@#$%^&*()_+-=[]{}|;:,.<>?',
    similar: '0O1l|',
    ambiguous: '{}[]()/\\\'"`~,;<>.?'
  };

  // Improved and realistic password strength calculation
  const calculateStrength = useCallback((password: string): { 
    strength: GeneratedPassword['strength'], 
    score: number, 
    entropy: number 
  } => {
    // Calculate charset size based on actual characters present
    let charsetSize = 0;
    const hasLower = /[a-z]/.test(password);
    const hasUpper = /[A-Z]/.test(password);
    const hasNumbers = /[0-9]/.test(password);
    const hasSymbols = /[^A-Za-z0-9]/.test(password);
    
    if (hasLower) charsetSize += 26;
    if (hasUpper) charsetSize += 26;
    if (hasNumbers) charsetSize += 10;
    if (hasSymbols) charsetSize += 32; // Common symbols
    
    // Calculate entropy (bits of randomness) - this is the key metric
    const entropy = Math.log2(Math.pow(charsetSize, password.length));
    
    // Base score from entropy (most important factor)
    let score = 0;
    
    // Entropy-based scoring (this should be the primary factor)
    if (entropy >= 200) score = 100;      // Extremely strong (64+ char with full charset)
    else if (entropy >= 150) score = 95;  // Excellent (48+ char with full charset)
    else if (entropy >= 128) score = 90;  // Cryptographically strong (40+ char)
    else if (entropy >= 100) score = 85;  // Very strong (32+ char)
    else if (entropy >= 80) score = 75;   // Strong (25+ char)
    else if (entropy >= 60) score = 65;   // Good (19+ char)
    else if (entropy >= 40) score = 45;   // Medium (13+ char)
    else if (entropy >= 28) score = 25;   // Weak (9+ char)
    else score = 10;                      // Very weak
    
    // Bonus for character variety (max +10 points)
    const varietyCount = [hasLower, hasUpper, hasNumbers, hasSymbols].filter(Boolean).length;
    const varietyBonus = Math.min((varietyCount - 1) * 3, 10); // 0, 3, 6, 9 points
    score += varietyBonus;
    
    // Bonus for length (encouraging longer passwords) - max +10 points
    let lengthBonus = 0;
    if (password.length >= 64) lengthBonus = 10;
    else if (password.length >= 32) lengthBonus = 8;
    else if (password.length >= 24) lengthBonus = 6;
    else if (password.length >= 16) lengthBonus = 4;
    else if (password.length >= 12) lengthBonus = 2;
    
    score += lengthBonus;
    
    // Penalty for repeated patterns (max -15 points)
    const uniqueChars = new Set(password).size;
    const uniquenessRatio = uniqueChars / password.length;
    let uniquenessBonus = 0;
    
    if (uniquenessRatio >= 0.9) uniquenessBonus = 5;      // Excellent uniqueness
    else if (uniquenessRatio >= 0.8) uniquenessBonus = 3; // Good uniqueness  
    else if (uniquenessRatio >= 0.7) uniquenessBonus = 1; // Decent uniqueness
    else if (uniquenessRatio < 0.5) uniquenessBonus = -10; // Poor uniqueness (penalty)
    else if (uniquenessRatio < 0.6) uniquenessBonus = -5;  // Below average
    
    score += uniquenessBonus;
    
    // Check for common patterns and penalize
    let patternPenalty = 0;
    
    // Sequential characters (abc, 123, etc.)
    for (let i = 0; i < password.length - 2; i++) {
      const char1 = password.charCodeAt(i);
      const char2 = password.charCodeAt(i + 1);
      const char3 = password.charCodeAt(i + 2);
      
      if (char2 === char1 + 1 && char3 === char2 + 1) {
        patternPenalty += 5; // Found sequential pattern
      }
    }
    
    // Repeated substrings
    for (let len = 2; len <= Math.floor(password.length / 3); len++) {
      for (let i = 0; i <= password.length - len * 2; i++) {
        const substring = password.substring(i, i + len);
        const remaining = password.substring(i + len);
        if (remaining.includes(substring)) {
          patternPenalty += len; // Penalty based on repeated substring length
        }
      }
    }
    
    score -= Math.min(patternPenalty, 15);
    
    // Ensure score is within bounds
    score = Math.max(0, Math.min(100, Math.round(score)));
    
    // Determine strength category based on final score AND entropy
    let strength: GeneratedPassword['strength'];
    
    if (score >= 95 && entropy >= 150) {
      strength = 'extremely-strong';
    } else if (score >= 85 && entropy >= 100) {
      strength = 'very-strong';
    } else if (score >= 70 && entropy >= 60) {
      strength = 'strong';
    } else if (score >= 50 && entropy >= 40) {
      strength = 'medium';
    } else {
      strength = 'weak';
    }
    
    return { strength, score, entropy: Math.round(entropy) };
  }, []);

  // Generate single password
  const generatePassword = useCallback((): string => {
    let charset = '';
    
    if (settings.includeLowercase) charset += charSets.lowercase;
    if (settings.includeUppercase) charset += charSets.uppercase;
    if (settings.includeNumbers) charset += charSets.numbers;
    if (settings.includeSymbols) charset += charSets.symbols;
    
    if (settings.excludeSimilar) {
      charSets.similar.split('').forEach(char => {
        charset = charset.replace(new RegExp(char, 'g'), '');
      });
    }
    
    if (settings.excludeAmbiguous) {
      charSets.ambiguous.split('').forEach(char => {
        charset = charset.replace(new RegExp(char.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g'), '');
      });
    }
    
    if (charset.length === 0) {
      charset = charSets.lowercase; // Fallback
    }
    
    let password = '';
    for (let i = 0; i < settings.length; i++) {
      password += charset.charAt(Math.floor(Math.random() * charset.length));
    }
    
    return password;
  }, [settings]);

  // Generate multiple passwords
  const generatePasswords = useCallback(async () => {
    setGenerating(true);
    
    // Simulate generation delay for better UX
    await new Promise(resolve => setTimeout(resolve, 300));
    
    const newPasswords: GeneratedPassword[] = [];
    
    for (let i = 0; i < 6; i++) {
      const password = generatePassword();
      const { strength, score, entropy } = calculateStrength(password);
      
      newPasswords.push({
        id: `pwd-${Date.now()}-${i}`,
        password,
        strength,
        score,
        entropy,
        copied: false,
        saved: false
      });
    }
    
    setPasswords(newPasswords);
    setGenerating(false);
  }, [generatePassword, calculateStrength]);

  // Copy password to clipboard
  const copyPassword = useCallback(async (id: string, password: string) => {
    try {
      await navigator.clipboard.writeText(password);
      setPasswords(prev => prev.map(p => 
        p.id === id ? { ...p, copied: true } : { ...p, copied: false }
      ));
      
      // Reset copied state after 2 seconds
      setTimeout(() => {
        setPasswords(prev => prev.map(p => 
          p.id === id ? { ...p, copied: false } : p
        ));
      }, 2000);
    } catch (error) {
      console.error('Failed to copy password:', error);
    }
  }, []);

  // Save password to stored passwords
  const handleSavePassword = useCallback((password: string) => {
    setPasswordToSave(password);
    setShowAddModal(true);
  }, []);

  // Handle saving password through modal
  const handleAddPasswordSubmit = useCallback(async (passwordData: AddPasswordData) => {
    try {
      // Usar el hook createAccount en lugar de lógica personalizada
      await createAccount(passwordData);
      
      // Mark the password as saved
      setPasswords(prev => prev.map(p => 
        p.password === passwordToSave ? { ...p, saved: true } : p
      ));
      
      // Close modal and reset
      setShowAddModal(false);
      setPasswordToSave('');
      
      return { success: true };
    } catch (error) {
      console.error('Error saving password:', error);
      return { 
        success: false, 
        error: error instanceof Error ? error.message : 'Error al guardar la contraseña' 
      };
    }
  }, [passwordToSave, createAccount]);

  // Update settings
  const updateSetting = useCallback(<K extends keyof PasswordSettings>(
    key: K, 
    value: PasswordSettings[K]
  ) => {
    setSettings(prev => ({ ...prev, [key]: value }));
  }, []);

  // Generate initial passwords
  useEffect(() => {
    generatePasswords();
  }, [settings]);

  // Get strength color
  const getStrengthColor = (strength: GeneratedPassword['strength']) => {
    switch (strength) {
      case 'weak': return colors.error;
      case 'medium': return colors.warning;
      case 'strong': return '#10b981';
      case 'very-strong': return '#059669';
      case 'extremely-strong': return '#047857';
      default: return colors.textMuted;
    }
  };

  // Get strength text
  const getStrengthText = (strength: GeneratedPassword['strength']) => {
    switch (strength) {
      case 'weak': return 'Débil';
      case 'medium': return 'Media';
      case 'strong': return 'Fuerte';
      case 'very-strong': return 'Muy Fuerte';
      case 'extremely-strong': return 'Extremadamente Fuerte';
      default: return 'Desconocida';
    }
  };

  return (
    <div className="p-6 space-y-6" style={{ backgroundColor: colors.background, minHeight: '100vh' }}>
      {/* Header */}
      <div className="mb-8">
        <h1 className="text-3xl font-bold mb-2" style={{ color: colors.textPrimary }}>
          Generador de Contraseñas 🔐
        </h1>
        <p style={{ color: colors.textSecondary }}>
          Genera contraseñas seguras y únicas con configuración personalizada
        </p>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-4 gap-6">
        {/* Settings Panel */}
        <div className="xl:col-span-1">
          <div 
            className="rounded-lg shadow-md p-6 sticky top-6"
            style={{ backgroundColor: colors.surface }}
          >
            <div className="flex items-center mb-6">
              <Settings className="w-5 h-5 mr-2" style={{ color: colors.primary }} />
              <h2 className="text-lg font-semibold" style={{ color: colors.textPrimary }}>
                Configuración
              </h2>
            </div>

            <div className="space-y-6">
              {/* Length Slider */}
              <div>
                <label className="block text-sm font-medium mb-2" style={{ color: colors.textSecondary }}>
                  Longitud: {settings.length}
                </label>
                <input
                  type="range"
                  min="8"
                  max="128"
                  value={settings.length}
                  onChange={(e) => updateSetting('length', parseInt(e.target.value))}
                  className="w-full h-2 rounded-lg appearance-none cursor-pointer"
                  style={{ 
                    background: `linear-gradient(to right, ${colors.primary} 0%, ${colors.primary} ${((settings.length - 8) / 120) * 100}%, ${colors.border} ${((settings.length - 8) / 120) * 100}%, ${colors.border} 100%)`,
                  }}
                />
                <div className="flex justify-between text-xs mt-1" style={{ color: colors.textMuted }}>
                  <span>8</span>
                  <span>128</span>
                </div>
              </div>

              {/* Character Type Checkboxes */}
              <div className="space-y-3">
                <h3 className="text-sm font-medium" style={{ color: colors.textSecondary }}>
                  Tipos de Caracteres
                </h3>
                
                {[
                  { key: 'includeUppercase' as const, label: 'Mayúsculas (A-Z)', example: 'ABC' },
                  { key: 'includeLowercase' as const, label: 'Minúsculas (a-z)', example: 'abc' },
                  { key: 'includeNumbers' as const, label: 'Números (0-9)', example: '123' },
                  { key: 'includeSymbols' as const, label: 'Símbolos (!@#)', example: '!@#' }
                ].map(({ key, label, example }) => (
                  <label key={key} className="flex items-center">
                    <input
                      type="checkbox"
                      checked={settings[key]}
                      onChange={(e) => updateSetting(key, e.target.checked)}
                      className="w-4 h-4 rounded mr-3 cursor-pointer"
                      style={{ accentColor: colors.primary }}
                    />
                    <div className="flex-1">
                      <span className="text-sm" style={{ color: colors.textPrimary }}>{label}</span>
                      <span 
                        className="text-xs ml-2 px-2 py-0.5 rounded font-mono"
                        style={{ 
                          backgroundColor: colors.backgroundTertiary,
                          color: colors.textMuted 
                        }}
                      >
                        {example}
                      </span>
                    </div>
                  </label>
                ))}
              </div>

              {/* Advanced Options */}
              <div className="space-y-3">
                <h3 className="text-sm font-medium" style={{ color: colors.textSecondary }}>
                  Opciones Avanzadas
                </h3>
                
                {[
                  { 
                    key: 'excludeSimilar' as const, 
                    label: 'Excluir caracteres similares', 
                    description: 'Evita 0, O, 1, l, |' 
                  },
                  { 
                    key: 'excludeAmbiguous' as const, 
                    label: 'Excluir caracteres ambiguos', 
                    description: 'Evita {}, [], (), /, \\, etc.' 
                  }
                ].map(({ key, label, description }) => (
                  <label key={key} className="flex items-start">
                    <input
                      type="checkbox"
                      checked={settings[key]}
                      onChange={(e) => updateSetting(key, e.target.checked)}
                      className="w-4 h-4 rounded mt-0.5 mr-3 cursor-pointer"
                      style={{ accentColor: colors.primary }}
                    />
                    <div>
                      <span className="text-sm" style={{ color: colors.textPrimary }}>{label}</span>
                      <p className="text-xs mt-0.5" style={{ color: colors.textMuted }}>
                        {description}
                      </p>
                    </div>
                  </label>
                ))}
              </div>

              {/* Generate Button */}
              <button
                onClick={generatePasswords}
                disabled={generating}
                className="w-full flex items-center justify-center gap-2 py-3 px-4 rounded-lg font-medium transition-all hover:scale-105 disabled:opacity-50 disabled:cursor-not-allowed"
                style={{ 
                  backgroundColor: colors.primary,
                  color: colors.primaryText 
                }}
              >
                {generating ? (
                  <RefreshCw className="w-4 h-4 animate-spin" />
                ) : (
                  <Zap className="w-4 h-4" />
                )}
                {generating ? 'Generando...' : 'Generar Nuevas'}
              </button>
            </div>
          </div>
        </div>

        {/* Generated Passwords */}
        <div className="xl:col-span-3">
          <div className="space-y-6">
            {/* Stats Header */}
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
              <div 
                className="p-4 rounded-lg border"
                style={{ 
                  backgroundColor: colors.surface,
                  borderColor: colors.border 
                }}
              >
                <div className="flex items-center">
                  <div 
                    className="p-2 rounded-full mr-3"
                    style={{ backgroundColor: `${colors.primary}15` }}
                  >
                    <Key className="w-5 h-5" style={{ color: colors.primary }} />
                  </div>
                  <div>
                    <p className="text-2xl font-bold" style={{ color: colors.textPrimary }}>
                      {passwords.length}
                    </p>
                    <p className="text-sm" style={{ color: colors.textSecondary }}>
                      Contraseñas Generadas
                    </p>
                  </div>
                </div>
              </div>

              <div 
                className="p-4 rounded-lg border"
                style={{ 
                  backgroundColor: colors.surface,
                  borderColor: colors.border 
                }}
              >
                <div className="flex items-center">
                  <div 
                    className="p-2 rounded-full mr-3"
                    style={{ backgroundColor: `${colors.success}15` }}
                  >
                    <Shield className="w-5 h-5" style={{ color: colors.success }} />
                  </div>
                  <div>
                    <p className="text-2xl font-bold" style={{ color: colors.textPrimary }}>
                      {Math.round(passwords.reduce((acc, p) => acc + p.score, 0) / passwords.length) || 0}%
                    </p>
                    <p className="text-sm" style={{ color: colors.textSecondary }}>
                      Seguridad Promedio
                    </p>
                  </div>
                </div>
              </div>

              <div 
                className="p-4 rounded-lg border"
                style={{ 
                  backgroundColor: colors.surface,
                  borderColor: colors.border 
                }}
              >
                <div className="flex items-center">
                  <div 
                    className="p-2 rounded-full mr-3"
                    style={{ backgroundColor: `${colors.warning}15` }}
                  >
                    <Lock className="w-5 h-5" style={{ color: colors.warning }} />
                  </div>
                  <div>
                    <p className="text-2xl font-bold" style={{ color: colors.textPrimary }}>
                      {Math.round(passwords.reduce((acc, p) => acc + p.entropy, 0) / passwords.length) || 0}
                    </p>
                    <p className="text-sm" style={{ color: colors.textSecondary }}>
                      Entropía Promedio (bits)
                    </p>
                  </div>
                </div>
              </div>

              <div 
                className="p-4 rounded-lg border"
                style={{ 
                  backgroundColor: colors.surface,
                  borderColor: colors.border 
                }}
              >
                <div className="flex items-center">
                  <div 
                    className="p-2 rounded-full mr-3"
                    style={{ backgroundColor: `${colors.info}15` }}
                  >
                    <Save className="w-5 h-5" style={{ color: colors.info }} />
                  </div>
                  <div>
                    <p className="text-2xl font-bold" style={{ color: colors.textPrimary }}>
                      {passwords.filter(p => p.saved).length}
                    </p>
                    <p className="text-sm" style={{ color: colors.textSecondary }}>
                      Contraseñas Guardadas
                    </p>
                  </div>
                </div>
              </div>
            </div>

            {/* Password Cards */}
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <h2 className="text-xl font-semibold" style={{ color: colors.textPrimary }}>
                  Contraseñas Generadas
                </h2>
                <div className="flex gap-2">
                  <button
                    onClick={() => {
                      const allPasswords = passwords.map(p => p.password).join('\n');
                      navigator.clipboard.writeText(allPasswords);
                    }}
                    className="flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium transition-all hover:scale-105"
                    style={{ 
                      backgroundColor: colors.backgroundTertiary,
                      color: colors.textSecondary 
                    }}
                  >
                    <Download className="w-4 h-4" />
                    Exportar Todo
                  </button>
                </div>
              </div>

              {generating ? (
                <div className="flex items-center justify-center py-12">
                  <RefreshCw 
                    className="w-8 h-8 animate-spin mr-3" 
                    style={{ color: colors.primary }} 
                  />
                  <span style={{ color: colors.textSecondary }}>
                    Generando contraseñas seguras...
                  </span>
                </div>
              ) : (
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                  {passwords.map((passwordData) => (
                    <div
                      key={passwordData.id}
                      className="p-6 rounded-lg border transition-all hover:shadow-lg"
                      style={{ 
                        backgroundColor: colors.surface,
                        borderColor: colors.border 
                      }}
                    >
                      {/* Password Header */}
                      <div className="flex items-center justify-between mb-4">
                        <div className="flex items-center">
                          <div 
                            className="w-3 h-3 rounded-full mr-2"
                            style={{ backgroundColor: getStrengthColor(passwordData.strength) }}
                          />
                          <div className="flex flex-col">
                            <span 
                              className="text-sm font-medium"
                              style={{ color: getStrengthColor(passwordData.strength) }}
                            >
                              {getStrengthText(passwordData.strength)} ({passwordData.score}%)
                            </span>
                            <span className="text-xs" style={{ color: colors.textMuted }}>
                              {passwordData.entropy} bits de entropía
                            </span>
                          </div>
                        </div>
                        <div className="flex items-center gap-1">
                          <button
                            onClick={() => handleSavePassword(passwordData.password)}
                            className="p-2 rounded-lg transition-all hover:scale-105"
                            style={{ 
                              backgroundColor: passwordData.saved ? colors.success : colors.info,
                              color: 'white'
                            }}
                            disabled={passwordData.saved}
                            title={passwordData.saved ? 'Ya guardada' : 'Guardar contraseña'}
                          >
                            {passwordData.saved ? (
                              <Check className="w-4 h-4" />
                            ) : (
                              <Plus className="w-4 h-4" />
                            )}
                          </button>
                          <button
                            onClick={() => copyPassword(passwordData.id, passwordData.password)}
                            className="p-2 rounded-lg transition-all hover:scale-105"
                            style={{ 
                              backgroundColor: passwordData.copied ? colors.success : colors.primary,
                              color: 'white'
                            }}
                          >
                            {passwordData.copied ? (
                              <Check className="w-4 h-4" />
                            ) : (
                              <Copy className="w-4 h-4" />
                            )}
                          </button>
                        </div>
                      </div>

                      {/* Password Display - Now always visible */}
                      <div 
                        className="p-4 rounded-lg border font-mono text-sm break-all select-all cursor-text"
                        style={{ 
                          backgroundColor: colors.backgroundSecondary,
                          borderColor: colors.border,
                          color: colors.textPrimary,
                          wordBreak: 'break-all',
                          lineHeight: '1.4'
                        }}
                      >
                        {passwordData.password}
                      </div>

                      {/* Strength Bar */}
                      <div className="mt-3">
                        <div 
                          className="h-2 rounded-full"
                          style={{ backgroundColor: colors.backgroundTertiary }}
                        >
                          <div 
                            className="h-2 rounded-full transition-all duration-500"
                            style={{ 
                              backgroundColor: getStrengthColor(passwordData.strength),
                              width: `${passwordData.score}%` 
                            }}
                          />
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Tips Section */}
      <div 
        className="rounded-lg p-6 border" 
        style={{ 
          background: `linear-gradient(to right, ${colors.primary}10, ${colors.primary}05)`,
          borderColor: colors.border
        }}
      >
        <div className="flex items-center mb-4">
          <Shield className="w-6 h-6 mr-2" style={{ color: colors.primary }} />
          <h3 className="text-lg font-semibold" style={{ color: colors.textPrimary }}>
            Consejos de Seguridad
          </h3>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          <div className="flex items-start">
            <div 
              className="w-2 h-2 rounded-full mt-2 mr-3 flex-shrink-0"
              style={{ backgroundColor: colors.success }}
            />
            <div>
              <p className="text-sm font-medium" style={{ color: colors.textPrimary }}>
                Longitud Óptima
              </p>
              <p className="text-xs mt-1" style={{ color: colors.textSecondary }}>
                Usa al menos 16 caracteres para mayor seguridad
              </p>
            </div>
          </div>
          
          <div className="flex items-start">
            <div 
              className="w-2 h-2 rounded-full mt-2 mr-3 flex-shrink-0"
              style={{ backgroundColor: colors.success }}
            />
            <div>
              <p className="text-sm font-medium" style={{ color: colors.textPrimary }}>
                Alta Entropía
              </p>
              <p className="text-xs mt-1" style={{ color: colors.textSecondary }}>
                Busca al menos 80 bits de entropía
              </p>
            </div>
          </div>
          
          <div className="flex items-start">
            <div 
              className="w-2 h-2 rounded-full mt-2 mr-3 flex-shrink-0"
              style={{ backgroundColor: colors.success }}
            />
            <div>
              <p className="text-sm font-medium" style={{ color: colors.textPrimary }}>
                Variedad de Caracteres
              </p>
              <p className="text-xs mt-1" style={{ color: colors.textSecondary }}>
                Combina mayúsculas, minúsculas, números y símbolos
              </p>
            </div>
          </div>
          
          <div className="flex items-start">
            <div 
              className="w-2 h-2 rounded-full mt-2 mr-3 flex-shrink-0"
              style={{ backgroundColor: colors.success }}
            />
            <div>
              <p className="text-sm font-medium" style={{ color: colors.textPrimary }}>
                Única para Cada Cuenta
              </p>
              <p className="text-xs mt-1" style={{ color: colors.textSecondary }}>
                Nunca reutilices la misma contraseña
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Add Password Modal */}
      <AddPasswordModal
        isOpen={showAddModal}
        onClose={() => {
          setShowAddModal(false);
          setPasswordToSave('');
        }}
        onSubmit={handleAddPasswordSubmit}
        prefilledPassword={passwordToSave}
      />
    </div>
  );
};