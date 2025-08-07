// types.ts - Definiciones de tipos para el gestor de contraseñas

export interface StatCardProps {
  title: string;
  value: string;
  icon: React.ComponentType<{ className?: string }>;
  color: string;
  trend?: number;
}

export interface ActivityItemProps {
  icon: React.ComponentType<{ className?: string }>;
  title: string;
  description: string;
  time: string;
  type: 'success' | 'warning' | 'error' | 'info';
}

export interface QuickActionCardProps {
  title: string;
  description: string;
  icon: React.ComponentType<{ className?: string }>;
  color: string;
  onClick: () => void;
}

export interface HomePageProps {
  setCurrentPage: (page: string) => void;
}

export interface HeaderProps {
  toggleSidebar: () => void;
  userName?: string;
}

export interface SidebarProps {
  isOpen: boolean;
  toggleSidebar: () => void;
  currentPage: string;
  setCurrentPage: (page: string) => void;
}

export interface LayoutProps {
  children: React.ReactNode;
  currentPage: string;
  setCurrentPage: (page: string) => void;
}

export interface SettingsState {
  theme: 'light' | 'dark' | 'pink';
  requirePasswordModify: boolean;
  requirePasswordDelete: boolean;
  notifications: 'enabled' | 'disabled';
}

export interface MenuItem {
  id: string;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  href: string;
}