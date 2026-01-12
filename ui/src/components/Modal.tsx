
import React, { useEffect } from 'react';
import { X } from 'lucide-react';
import clsx from 'clsx';

interface ModalProps {
    isOpen: boolean;
    onClose: () => void;
    title: string;
    children: React.ReactNode;
    footer?: React.ReactNode;
    maxWidth?: string;
}

export const Modal: React.FC<ModalProps> = ({
    isOpen, onClose, title, children, footer, maxWidth = 'max-w-md'
}) => {

    useEffect(() => {
        const handleEsc = (e: KeyboardEvent) => {
            if (e.key === 'Escape') onClose();
        };
        window.addEventListener('keydown', handleEsc);
        return () => window.removeEventListener('keydown', handleEsc);
    }, [onClose]);

    if (!isOpen) return null;

    return (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
            <div className={clsx("w-full bg-[#25262b] border border-[#373a40] rounded-lg shadow-2xl flex flex-col max-h-[90vh]", maxWidth)}>
                {/* Header */}
                <div className="flex justify-between items-center p-4 border-b border-[#373a40]">
                    <h3 className="text-lg font-bold text-white">{title}</h3>
                    <button onClick={onClose} className="text-gray-400 hover:text-white transition-colors">
                        <X size={20} />
                    </button>
                </div>

                {/* Body */}
                <div className="p-4 overflow-y-auto text-gray-300">
                    {children}
                </div>

                {/* Footer */}
                {footer && (
                    <div className="p-4 border-t border-[#373a40] bg-[#1a1b1e]/50 rounded-b-lg flex justify-end gap-2">
                        {footer}
                    </div>
                )}
            </div>
        </div>
    );
};
