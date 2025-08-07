// frontend/src/types/django.ts
// Tipos para la integración con Django

export interface DjangoUser {
  id: number | null
  username: string
  email: string
  isAuthenticated: boolean
}

export interface DjangoData {
  user: DjangoUser
  csrfToken: string
  urls: Record<string, string>
}

// Extender la interfaz Window global
declare global {
  interface Window {
    DjangoData?: DjangoData
  }
}

export {}