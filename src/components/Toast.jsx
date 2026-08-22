import React, { useState, useCallback } from 'react';
import { CheckCircle, AlertTriangle, X, Info, AlertCircle } from 'lucide-react';
import { clsx } from 'clsx';
import { ToastContext } from '../hooks/useToast';

const TOAST_TYPES = {
    success: {
        icon: CheckCircle,
        bgColor: 'bg-green-50',
        borderColor: 'border-green-500',
        textColor: 'text-green-800',
        iconColor: 'text-green-600',
    },
    error: {
        icon: AlertCircle,
        bgColor: 'bg-red-50',
        borderColor: 'border-red-500',
        textColor: 'text-red-800',
        iconColor: 'text-red-600',
    },
    warning: {
        icon: AlertTriangle,
        bgColor: 'bg-yellow-50',
        borderColor: 'border-yellow-500',
        textColor: 'text-yellow-800',
        iconColor: 'text-yellow-600',
    },
    info: {
        icon: Info,
        bgColor: 'bg-blue-50',
        borderColor: 'border-blue-500',
        textColor: 'text-blue-800',
        iconColor: 'text-blue-600',
    },
};

const Toast = ({ toast, onDismiss }) => {
    const config = TOAST_TYPES[toast.type] || TOAST_TYPES.info;
    const Icon = config.icon;

    return (
        <div
            className={clsx(
                'flex items-start gap-3 p-4 rounded-lg border shadow-lg max-w-sm',
                'animate-slide-in-right',
                config.bgColor,
                config.borderColor
            )}
            role="alert"
        >
            <Icon className={clsx('w-5 h-5 shrink-0 mt-0.5', config.iconColor)} />
            <div className="flex-1">
                {toast.title && (
                    <p className={clsx('font-semibold', config.textColor)}>{toast.title}</p>
                )}
                <p className={clsx('text-sm', config.textColor)}>{toast.message}</p>
            </div>
            <button
                onClick={() => onDismiss(toast.id)}
                className={clsx('shrink-0 p-1 rounded hover:bg-black/5', config.textColor)}
            >
                <X className="w-4 h-4" />
            </button>
        </div>
    );
};

export const ToastProvider = ({ children }) => {
    const [toasts, setToasts] = useState([]);

    const addToast = useCallback((message, type = 'info', title = null, duration = 4000) => {
        const id = Date.now() + Math.random();
        const toast = { id, message, type, title };

        setToasts(prev => [...prev, toast]);

        if (duration > 0) {
            setTimeout(() => {
                setToasts(prev => prev.filter(t => t.id !== id));
            }, duration);
        }

        return id;
    }, []);

    const dismissToast = useCallback((id) => {
        setToasts(prev => prev.filter(t => t.id !== id));
    }, []);

    const toast = {
        success: (message, title) => addToast(message, 'success', title),
        error: (message, title) => addToast(message, 'error', title),
        warning: (message, title) => addToast(message, 'warning', title),
        info: (message, title) => addToast(message, 'info', title),
    };

    return (
        <ToastContext.Provider value={toast}>
            {children}
            <div className="fixed bottom-4 right-4 z-50 flex flex-col gap-2">
                {toasts.map(t => (
                    <Toast key={t.id} toast={t} onDismiss={dismissToast} />
                ))}
            </div>
        </ToastContext.Provider>
    );
};

export default ToastProvider;
