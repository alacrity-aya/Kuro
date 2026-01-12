import React from 'react';
import { useStore } from '../store';
import { X, AlertCircle, CheckCircle, Info } from 'lucide-react';
import clsx from 'clsx';

export const ToastContainer = () => {
    const { toasts, removeToast } = useStore();

    if (toasts.length === 0) return null;

    return (
        <div className="fixed top-4 right-4 z-[100] flex flex-col gap-2 pointer-events-none">
            {toasts.map(toast => (
                <div
                    key={toast.id}
                    className={clsx(
                        "pointer-events-auto min-w-[300px] p-4 rounded shadow-lg border-l-4 flex items-start gap-3 animate-in slide-in-from-right-full transition-all duration-300",
                        toast.type === 'error' && "bg-[#25262b] border-red-500 text-red-100",
                        toast.type === 'success' && "bg-[#25262b] border-green-500 text-green-100",
                        toast.type === 'info' && "bg-[#25262b] border-blue-500 text-blue-100",
                    )}
                >
                    <div className="mt-0.5">
                        {toast.type === 'error' && <AlertCircle size={16} />}
                        {toast.type === 'success' && <CheckCircle size={16} />}
                        {toast.type === 'info' && <Info size={16} />}
                    </div>
                    <div className="flex-1 text-sm font-medium">{toast.title}</div>
                    <button
                        onClick={() => removeToast(toast.id)}
                        className="text-gray-400 hover:text-white transition-colors"
                    >
                        <X size={14} />
                    </button>
                </div>
            ))}
        </div>
    );
};
