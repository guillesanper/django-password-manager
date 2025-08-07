// frontend/src/types/index.ts
// Archivo principal de exportación de tipos

// Exportar todos los tipos desde sus archivos específicos
export * from './django'
export * from './components'
export * from './pages'

// Tipos comunes y utilitarios
export type Theme = 'light' | 'dark' | 'pink'
export type NotificationStatus = 'enabled' | 'disabled'
export type ActivityType = 'success' | 'warning' | 'error' | 'info'

// Tipos para API responses
export interface ApiResponse<T = any> {
  success: boolean
  data?: T
  message?: string
  errors?: Record<string, string[]>
}

// Tipos para formularios
export interface FormErrors {
  [key: string]: string[]
}

export interface FormField {
  name: string
  label: string
  type: 'text' | 'email' | 'password' | 'url' | 'select' | 'textarea'
  placeholder?: string
  required?: boolean
  options?: { value: string; label: string }[]
}