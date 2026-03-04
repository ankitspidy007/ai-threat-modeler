import React, { useState } from 'react';
import { Shield, Zap, Sparkles, Clock, Moon, Sun, Settings, ChevronLeft, ChevronRight, Info } from 'lucide-react';

const navItems = [
    { id: 'static', label: 'Static Analysis', icon: Zap, color: 'text-brand-primary', activeColor: 'bg-brand-primary' },
    { id: 'ai', label: 'AI Analysis', icon: Sparkles, color: 'text-purple-500', activeColor: 'bg-purple-600' },
    { id: 'history', label: 'History', icon: Clock, color: 'text-brand-secondary', activeColor: 'bg-brand-secondary' },
];

export default function Sidebar({ activeTab, onTabChange, darkMode, onToggleDarkMode }) {
    const [collapsed, setCollapsed] = useState(true);

    return (
        <aside
            className={`
        fixed left-0 top-0 h-screen z-50
        flex flex-col items-center
        transition-all duration-300 ease-in-out
        ${collapsed ? 'w-[68px]' : 'w-[220px]'}
        bg-white/95 dark:bg-brand-900/95
        backdrop-blur-xl
        border-r border-brand-200/60 dark:border-brand-700/60
        shadow-[4px_0_24px_-2px_rgba(0,0,0,0.06)]
        dark:shadow-[4px_0_24px_-2px_rgba(0,0,0,0.3)]
      `}
        >
            {/* Logo */}
            <div className={`
        flex items-center gap-3 w-full px-4 pt-5 pb-4
        ${collapsed ? 'justify-center' : 'justify-start'}
      `}>
                <div className="relative group cursor-pointer flex-shrink-0">
                    <div className="absolute inset-0 bg-brand-primary/20 blur-lg rounded-full opacity-0 group-hover:opacity-100 transition-opacity duration-500" />
                    <div className="relative w-9 h-9 rounded-xl bg-gradient-to-br from-brand-primary to-brand-accent flex items-center justify-center shadow-lg shadow-brand-primary/25">
                        <Shield className="w-5 h-5 text-white" />
                    </div>
                </div>
                {!collapsed && (
                    <div className="overflow-hidden animate-fade-in-up">
                        <h1 className="text-lg font-bold tracking-tight text-brand-900 dark:text-white whitespace-nowrap">AITM</h1>
                        <p className="text-[10px] font-mono text-brand-500 dark:text-brand-400 -mt-0.5">v2.0 • NLP/ML</p>
                    </div>
                )}
            </div>

            {/* Divider */}
            <div className={`w-8 h-px bg-brand-200 dark:bg-brand-700 mb-3 ${collapsed ? '' : 'w-[calc(100%-2rem)]'}`} />

            {/* Navigation */}
            <nav className="flex-1 w-full px-2 space-y-1">
                {navItems.map((item) => {
                    const Icon = item.icon;
                    const isActive = activeTab === item.id;

                    return (
                        <button
                            key={item.id}
                            onClick={() => onTabChange(item.id)}
                            title={collapsed ? item.label : undefined}
                            className={`
                group relative w-full flex items-center gap-3 rounded-xl
                transition-all duration-200 ease-out
                ${collapsed ? 'justify-center px-0 py-3' : 'px-3.5 py-2.5'}
                ${isActive
                                    ? 'bg-brand-50 dark:bg-brand-800/80 shadow-sm'
                                    : 'hover:bg-brand-50/80 dark:hover:bg-brand-800/40'
                                }
              `}
                        >
                            {/* Active indicator bar */}
                            {isActive && (
                                <div className={`
                  absolute left-0 top-1/2 -translate-y-1/2
                  w-[3px] h-6 rounded-r-full
                  ${item.activeColor}
                  shadow-lg
                `}
                                    style={{ boxShadow: `0 0 12px 2px ${item.id === 'static' ? 'rgba(79,70,229,0.4)' : item.id === 'ai' ? 'rgba(147,51,234,0.4)' : 'rgba(14,165,233,0.4)'}` }}
                                />
                            )}

                            <div className={`
                relative flex-shrink-0
                ${isActive ? item.color : 'text-brand-500 dark:text-brand-400 group-hover:text-brand-700 dark:group-hover:text-brand-200'}
                transition-colors duration-200
              `}>
                                <Icon className="w-5 h-5" />
                                {isActive && (
                                    <div className="absolute inset-0 blur-md opacity-40" style={{ color: 'inherit' }}>
                                        <Icon className="w-5 h-5" />
                                    </div>
                                )}
                            </div>

                            {!collapsed && (
                                <span className={`
                  text-sm font-medium whitespace-nowrap
                  ${isActive ? 'text-brand-900 dark:text-white' : 'text-brand-600 dark:text-brand-400 group-hover:text-brand-900 dark:group-hover:text-white'}
                  transition-colors duration-200
                `}>
                                    {item.label}
                                </span>
                            )}

                            {/* Tooltip for collapsed state */}
                            {collapsed && (
                                <div className="
                  absolute left-full ml-3 px-3 py-1.5
                  bg-brand-900 dark:bg-brand-100
                  text-white dark:text-brand-900
                  text-xs font-medium rounded-lg
                  opacity-0 invisible group-hover:opacity-100 group-hover:visible
                  transition-all duration-200
                  pointer-events-none whitespace-nowrap
                  shadow-xl z-50
                ">
                                    {item.label}
                                    <div className="absolute right-full top-1/2 -translate-y-1/2 border-4 border-transparent border-r-brand-900 dark:border-r-brand-100" />
                                </div>
                            )}
                        </button>
                    );
                })}
            </nav>

            {/* Bottom actions */}
            <div className={`w-full px-2 pb-4 space-y-1 ${collapsed ? '' : ''}`}>
                {/* Divider */}
                <div className={`mx-auto mb-2 h-px bg-brand-200 dark:bg-brand-700 ${collapsed ? 'w-8' : 'w-[calc(100%-1rem)]'}`} />

                {/* Dark mode toggle */}
                <button
                    onClick={onToggleDarkMode}
                    title={collapsed ? (darkMode ? 'Light mode' : 'Dark mode') : undefined}
                    className={`
            group relative w-full flex items-center gap-3 rounded-xl
            transition-all duration-200
            ${collapsed ? 'justify-center px-0 py-3' : 'px-3.5 py-2.5'}
            hover:bg-brand-50/80 dark:hover:bg-brand-800/40
          `}
                >
                    {darkMode
                        ? <Sun className="w-5 h-5 text-amber-400 transition-transform duration-300 group-hover:rotate-45" />
                        : <Moon className="w-5 h-5 text-brand-500 dark:text-brand-400 transition-transform duration-300 group-hover:-rotate-12" />
                    }
                    {!collapsed && (
                        <span className="text-sm font-medium text-brand-600 dark:text-brand-400 whitespace-nowrap">
                            {darkMode ? 'Light Mode' : 'Dark Mode'}
                        </span>
                    )}
                    {collapsed && (
                        <div className="absolute left-full ml-3 px-3 py-1.5 bg-brand-900 dark:bg-brand-100 text-white dark:text-brand-900 text-xs font-medium rounded-lg opacity-0 invisible group-hover:opacity-100 group-hover:visible transition-all duration-200 pointer-events-none whitespace-nowrap shadow-xl z-50">
                            {darkMode ? 'Light Mode' : 'Dark Mode'}
                            <div className="absolute right-full top-1/2 -translate-y-1/2 border-4 border-transparent border-r-brand-900 dark:border-r-brand-100" />
                        </div>
                    )}
                </button>

                {/* Collapse toggle */}
                <button
                    onClick={() => setCollapsed(!collapsed)}
                    title={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
                    className={`
            group relative w-full flex items-center gap-3 rounded-xl
            transition-all duration-200
            ${collapsed ? 'justify-center px-0 py-3' : 'px-3.5 py-2.5'}
            hover:bg-brand-50/80 dark:hover:bg-brand-800/40
          `}
                >
                    {collapsed
                        ? <ChevronRight className="w-5 h-5 text-brand-400 group-hover:text-brand-600 dark:group-hover:text-brand-200 transition-colors" />
                        : <ChevronLeft className="w-5 h-5 text-brand-400 group-hover:text-brand-600 dark:group-hover:text-brand-200 transition-colors" />
                    }
                    {!collapsed && (
                        <span className="text-sm font-medium text-brand-600 dark:text-brand-400 whitespace-nowrap">
                            Collapse
                        </span>
                    )}
                </button>
            </div>
        </aside>
    );
}
