import { createContext, useContext } from 'react';

// The context and its hook live apart from the provider component so that the
// provider module exports components only, which is what fast refresh needs.
export const ToastContext = createContext(null);

export const useToast = () => {
    const context = useContext(ToastContext);
    if (!context) {
        throw new Error('useToast must be used within a ToastProvider');
    }
    return context;
};
