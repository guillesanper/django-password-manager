import React, { useEffect, useState } from 'react';
import { Lock, ArrowRight, MailCheck, AlertCircle } from 'lucide-react';
import {
  InputField,
  AuthButton,
  AuthContainer,
  ApiError,
  InfoBox,
  AuthLink,
} from '../components/AuthComponents';
import { useAuth } from '../components/AuthProvider';
import { takeVerificationToken } from '../services/authService';

export interface VerifyEmailPageProps {
  onSwitchToLogin: () => void;
  onSwitchToRegister: () => void;
}

/**
 * Segundo paso del alta (N17). Se llega desde el enlace del correo, con el token en el fragmento
 * (`/verificar-email#token=…`). Pide la contraseña del alta: sin ella, quien diera de alta un email
 * ajeno conseguiría que el dueño, al pulsar el enlace, le activase la cuenta.
 *
 * Al confirmar, el servidor abre sesión y AuthProvider pasa a configurar la clave maestra, como
 * hacía antes el alta.
 */
export const VerifyEmailPage: React.FC<VerifyEmailPageProps> = ({
  onSwitchToLogin,
  onSwitchToRegister,
}) => {
  const { confirmRegistration } = useAuth();
  // Se lee al montar sin tocar la URL (el inicializador debe ser puro) y se borra después.
  const [token] = useState(() => new URLSearchParams(window.location.hash.slice(1)).get('token'));
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    takeVerificationToken();
  }, []);

  const handleSubmit = async () => {
    if (!token || !password || loading) return;
    setLoading(true);
    setError('');
    try {
      const result = await confirmRegistration(token, password);
      if (!result.success) {
        setError(result.error || 'No se pudo activar la cuenta');
      }
    } finally {
      setLoading(false);
    }
  };

  if (!token) {
    return (
      <AuthContainer
        title="Enlace no válido"
        subtitle="Este enlace de activación está incompleto"
        icon={
          <div className="p-3 rounded-full bg-gradient-to-r from-amber-500 to-orange-600">
            <AlertCircle className="w-8 h-8 text-white" />
          </div>
        }
      >
        <div className="space-y-6">
          <InfoBox variant="warning">
            <p className="text-sm">
              Abre el enlace tal como llegó en el correo. Si ha caducado, vuelve a registrarte.
            </p>
          </InfoBox>
          <AuthLink text="¿Necesitas otro enlace?" linkText="Regístrate de nuevo" onClick={onSwitchToRegister} />
          <AuthLink text="¿Ya tienes cuenta?" linkText="Inicia sesión aquí" onClick={onSwitchToLogin} />
        </div>
      </AuthContainer>
    );
  }

  return (
    <AuthContainer
      title="Activa tu cuenta"
      subtitle="Confirma la contraseña que elegiste al registrarte"
      icon={
        <div className="p-3 rounded-full bg-gradient-to-r from-emerald-500 to-teal-600">
          <MailCheck className="w-8 h-8 text-white" />
        </div>
      }
    >
      <div
        className="space-y-6"
        onKeyDown={(e) => {
          if (e.key === 'Enter') {
            e.preventDefault();
            handleSubmit();
          }
        }}
      >
        {error && <ApiError error={error} />}

        <InputField
          label="Contraseña"
          type="password"
          value={password}
          onChange={setPassword}
          placeholder="La contraseña de tu registro"
          icon={Lock}
          showPasswordToggle
          onTogglePassword={() => setShowPassword(!showPassword)}
          showPassword={showPassword}
          required
        />

        <AuthButton onClick={handleSubmit} loading={loading} disabled={loading || !password}>
          <span>Activar cuenta</span>
          <ArrowRight className="w-5 h-5" />
        </AuthButton>

        <AuthLink text="¿Ya activaste la cuenta?" linkText="Inicia sesión aquí" onClick={onSwitchToLogin} />
      </div>
    </AuthContainer>
  );
};
