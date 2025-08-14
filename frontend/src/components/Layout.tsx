import React, { useState } from 'react';
import { Header } from './Header';
import { Sidebar } from './Sidebar';

export interface LayoutProps {
  children: React.ReactNode;
  currentPage: string;
  setCurrentPage: (page: string) => void;
}

export const Layout: React.FC<LayoutProps> = ({ children, currentPage, setCurrentPage }) => {
  const [sidebarOpen, setSidebarOpen] = useState<boolean>(false);

  const toggleSidebar = (): void => {
    setSidebarOpen(!sidebarOpen);
  };

  return (
    <div className="flex h-screen" style={{ backgroundColor: 'var(--color-background)' }}>
      {/* Sidebar */}
      <Sidebar 
        isOpen={sidebarOpen} 
        toggleSidebar={toggleSidebar} 
        currentPage={currentPage}
        setCurrentPage={setCurrentPage}
      />

      {/* Main Content */}
      <div className="flex-1 flex flex-col overflow-hidden">
        <Header toggleSidebar={toggleSidebar} userName="John Doe" />
        
        <main 
          className="flex-1 overflow-x-hidden overflow-y-auto p-6"
          style={{ backgroundColor: 'var(--color-background)' }}
        >
          {children}
        </main>
      </div>
    </div>
  );
};