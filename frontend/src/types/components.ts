// frontend/src/types/components.ts
// Tipos para componentes de la UI

import React from 'react'

export interface StatCardProps {
  title: string
  value: string
  icon: React.ComponentType<{ className?: string }>
  color: string
  trend?: number
}

export interface ActivityItemProps {
  icon: React.ComponentType<{ className?: string }>
  title: string
  description: string
  time: string
  type: 'success' | 'warning' | 'error' | 'info'
}

export interface QuickActionCardProps {
  title: string
  description: string
  icon: React.ComponentType<{ className?: string }>
  color: string
  onClick: () => void
}

export interface HeaderProps {
  toggleSidebar: () => void
  userName?: string
}

export interface SidebarProps {
  isOpen: boolean
  toggleSidebar: () => void
  currentPage: string
  setCurrentPage: (page: string) => void
}

export interface LayoutProps {
  children: React.ReactNode
}

export interface MenuItem {
  id: string
  label: string
  icon: React.ComponentType<{ className?: string }>
  href: string
}