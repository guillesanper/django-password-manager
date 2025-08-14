// types/django.ts
export interface DjangoUser {
  id: number;
  username: string;
  email: string;
  firstName: string;
  lastName: string;
  isAuthenticated: boolean;
}

export interface DjangoData {
  user: DjangoUser;
  csrfToken?: string;
}

// Extender la interfaz Window global
declare global {
  interface Window {
    DjangoData?: DjangoData;
  }
}

export {};