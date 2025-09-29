import React from 'react';
import { CheckCircle } from 'lucide-react';

export const SaveMessage: React.FC = () => (
  <div className="fixed bottom-4 right-4 bg-green-100 border border-green-400 text-green-700 px-4 py-2 rounded shadow-md flex items-center">
    <CheckCircle className="w-5 h-5 mr-2" />
    <span>Configuración guardada con éxito</span>
  </div>
);
