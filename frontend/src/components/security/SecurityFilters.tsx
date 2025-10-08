import React from 'react';
import { Search, Filter } from 'lucide-react';

interface SecurityFiltersProps {
  searchTerm: string;
  onSearchChange: (value: string) => void;
  strengthFilter: string;
  onStrengthFilterChange: (value: string) => void;
  breachFilter: string;
  onBreachFilterChange: (value: string) => void;
}

export const SecurityFilters: React.FC<SecurityFiltersProps> = ({
  searchTerm,
  onSearchChange,
  strengthFilter,
  onStrengthFilterChange,
  breachFilter,
  onBreachFilterChange
}) => {

  return (
    <div className="security-filters-container">
      <div className="security-filters-content">
        <div className="security-filters-search">
          <Search className="security-filters-search-icon" />
          <input
            type="text"
            placeholder="Buscar contraseñas..."
            value={searchTerm}
            onChange={(e) => onSearchChange(e.target.value)}
            className="security-filters-search-input"
          />
        </div>
        
        <div className="security-filters-selects">
          <div className="security-filters-select-group">
            <Filter className="security-filters-icon" />
            <select
              value={strengthFilter}
              onChange={(e) => onStrengthFilterChange(e.target.value)}
              className="password-sort-select"
            >
              <option value="all">Todas las fortalezas</option>
              <option value="very_strong">Muy fuertes</option>
              <option value="strong">Fuertes</option>
              <option value="moderate">Moderadas</option>
              <option value="weak">Débiles</option>
              <option value="very_weak">Muy débiles</option>
            </select>
          </div>

          <select
            value={breachFilter}
            onChange={(e) => onBreachFilterChange(e.target.value)}
            className="password-sort-select"
          >
            <option value="all">Todas</option>
            <option value="breached">Comprometidas</option>
            <option value="safe">Seguras</option>
          </select>
        </div>
      </div>
    </div>
  );
};