import React, { useState } from 'react';
import { Shield, Zap, Sparkles, Clock, Moon, Sun, ChevronLeft, ChevronRight } from 'lucide-react';

const navItems = [
  { id: 'static', label: 'Static Analysis', icon: Zap, color: 'text-brand-primary', activeColor: 'bg-brand-primary' },
  { id: 'iac', label: 'IaC Analysis', icon: Shield, color: 'text-brand-success', activeColor: 'bg-brand-success' },
  { id: 'ai', label: 'AI Analysis', icon: Sparkles, color: 'text-sky-500', activeColor: 'bg-sky-500' },
  { id: 'history', label: 'History', icon: Clock, color: 'text-brand-secondary', activeColor: 'bg-brand-secondary' },
];

export default function Sidebar({ activeTab, onTabChange, darkMode, onToggleDarkMode }) {
  const [collapsed, setCollapsed] = useState(true);

  return (
    <aside
      className={`
        fixed left-0 top-0 z-50 flex h-screen flex-col items-center
        transition-all duration-300 ease-in-out
        ${collapsed ? 'w-[68px]' : 'w-[220px]'}
        border-r border-white/70 bg-white/82 shadow-[8px_0_32px_-18px_rgba(15,23,42,0.24)] backdrop-blur-xl
        dark:border-brand-700/60 dark:bg-brand-900/88 dark:shadow-[8px_0_32px_-18px_rgba(2,6,23,0.45)]
      `}
    >
      <div
        className={`
          flex w-full items-center gap-3 px-4 pb-4 pt-5
          ${collapsed ? 'justify-center' : 'justify-start'}
        `}
      >
        <div className="relative flex-shrink-0 cursor-pointer">
          <div className="absolute inset-0 rounded-full bg-brand-primary/20 blur-lg" />
          <div className="relative flex h-10 w-10 items-center justify-center rounded-2xl bg-gradient-to-br from-brand-primary to-brand-accent shadow-lg shadow-brand-primary/20">
            <Shield className="h-5 w-5 text-white" />
          </div>
        </div>
        {!collapsed && (
          <div className="overflow-hidden animate-fade-in-up">
            <h1 className="whitespace-nowrap text-lg font-bold tracking-tight text-brand-900 dark:text-white">Aegis Threat</h1>
            <p className="mt-0.5 text-[10px] font-mono text-brand-500 dark:text-brand-400">Modern Threat Modeling</p>
          </div>
        )}
      </div>

      <div className={`mb-3 h-px bg-gradient-to-r from-transparent via-brand-200 to-transparent dark:via-brand-700 ${collapsed ? 'w-8' : 'w-[calc(100%-2rem)]'}`} />

      <nav className="flex w-full flex-1 flex-col gap-1 px-2">
        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = activeTab === item.id;

          return (
            <button
              key={item.id}
              onClick={() => onTabChange(item.id)}
              title={collapsed ? item.label : undefined}
              className={`
                group relative flex w-full items-center gap-3 rounded-2xl transition-all duration-200 ease-out
                ${collapsed ? 'justify-center px-0 py-3' : 'px-3.5 py-2.5'}
                ${isActive
                  ? 'bg-white shadow-[0_10px_30px_-20px_rgba(15,23,42,0.55)] dark:bg-brand-800/90'
                  : 'hover:bg-white/70 dark:hover:bg-brand-800/45'
                }
              `}
            >
              {isActive && (
                <div
                  className={`
                    absolute left-0 top-1/2 h-6 w-[3px] -translate-y-1/2 rounded-r-full
                    ${item.activeColor}
                  `}
                />
              )}

              <div
                className={`
                  relative flex-shrink-0 transition-colors duration-200
                  ${isActive ? item.color : 'text-brand-500 group-hover:text-brand-700 dark:text-brand-400 dark:group-hover:text-brand-200'}
                `}
              >
                <Icon className="h-5 w-5" />
              </div>

              {!collapsed && (
                <span
                  className={`
                    whitespace-nowrap text-sm font-medium transition-colors duration-200
                    ${isActive ? 'text-brand-900 dark:text-white' : 'text-brand-600 group-hover:text-brand-900 dark:text-brand-400 dark:group-hover:text-white'}
                  `}
                >
                  {item.label}
                </span>
              )}

              {collapsed && (
                <div className="pointer-events-none absolute left-full ml-3 whitespace-nowrap rounded-lg bg-brand-900 px-3 py-1.5 text-xs font-medium text-white opacity-0 invisible shadow-xl transition-all duration-200 group-hover:visible group-hover:opacity-100 dark:bg-brand-100 dark:text-brand-900">
                  {item.label}
                  <div className="absolute right-full top-1/2 -translate-y-1/2 border-4 border-transparent border-r-brand-900 dark:border-r-brand-100" />
                </div>
              )}
            </button>
          );
        })}
      </nav>

      <div className="w-full space-y-1 px-2 pb-4">
        <div className={`mx-auto mb-2 h-px bg-gradient-to-r from-transparent via-brand-200 to-transparent dark:via-brand-700 ${collapsed ? 'w-8' : 'w-[calc(100%-1rem)]'}`} />

        <button
          onClick={onToggleDarkMode}
          title={collapsed ? (darkMode ? 'Light mode' : 'Dark mode') : undefined}
          className={`
            group relative flex w-full items-center gap-3 rounded-2xl transition-all duration-200
            ${collapsed ? 'justify-center px-0 py-3' : 'px-3.5 py-2.5'}
            hover:bg-white/70 dark:hover:bg-brand-800/45
          `}
        >
          {darkMode
            ? <Sun className="h-5 w-5 text-amber-400 transition-transform duration-300 group-hover:rotate-45" />
            : <Moon className="h-5 w-5 text-brand-500 transition-transform duration-300 group-hover:-rotate-12 dark:text-brand-400" />}
          {!collapsed && (
            <span className="whitespace-nowrap text-sm font-medium text-brand-600 dark:text-brand-400">
              {darkMode ? 'Light Mode' : 'Dark Mode'}
            </span>
          )}
        </button>

        <button
          onClick={() => setCollapsed(!collapsed)}
          title={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          className={`
            group relative flex w-full items-center gap-3 rounded-2xl transition-all duration-200
            ${collapsed ? 'justify-center px-0 py-3' : 'px-3.5 py-2.5'}
            hover:bg-white/70 dark:hover:bg-brand-800/45
          `}
        >
          {collapsed
            ? <ChevronRight className="h-5 w-5 text-brand-400 transition-colors group-hover:text-brand-600 dark:group-hover:text-brand-200" />
            : <ChevronLeft className="h-5 w-5 text-brand-400 transition-colors group-hover:text-brand-600 dark:group-hover:text-brand-200" />}
          {!collapsed && (
            <span className="whitespace-nowrap text-sm font-medium text-brand-600 dark:text-brand-400">
              Collapse
            </span>
          )}
        </button>
      </div>
    </aside>
  );
}
