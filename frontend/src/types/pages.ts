// frontend/src/types/pages.ts
// Tipos específicos para las páginas

export interface HomePageProps {
  setCurrentPage?: (page: string) => void
}

export interface SettingsState {
  theme: 'light' | 'dark' | 'pink'
  requirePasswordModify: boolean
  requirePasswordDelete: boolean
  notifications: 'enabled' | 'disabled'
}

// Tipos para el gestor de contraseñas
export interface PasswordEntry {
  id: string
  title: string
  username: string
  email?: string
  website?: string
  category: string
  createdAt: Date
  updatedAt: Date
  isFavorite: boolean
}

export interface PasswordCategory {
  id: string
  name: string
  color: string
  icon: string
}

// Tipos para el generador de contraseñas
export interface PasswordGeneratorOptions {
  length: number
  includeUppercase: boolean
  includeLowercase: boolean
  includeNumbers: boolean
  includeSymbols: boolean
  excludeSimilar: boolean
  excludeAmbiguous: boolean
}