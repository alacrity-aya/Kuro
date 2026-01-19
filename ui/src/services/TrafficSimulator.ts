// src/services/TrafficSimulator.ts
import type { TrafficStats } from '../types';

type Callback = (data: Record<string, TrafficStats>) => void;

export class TrafficSimulator {
    private intervalId: number | null = null;
    private listeners: Set<Callback> = new Set();

    subscribe(callback: Callback) {
        this.listeners.add(callback);
        if (this.intervalId === null) {
            this.start();
        }
        return () => {
            this.listeners.delete(callback);
            if (this.listeners.size === 0) this.stop();
        };
    }

    private start() {
        console.log("[Simulator] Starting traffic generation...");
        this.intervalId = window.setInterval(() => {
            const mockData: Record<string, TrafficStats> = {};
            const now = Date.now();


            const baseValue = Math.abs(Math.sin(now / 2000)) * 10000000;


            const stats: TrafficStats = {
                timestamp: now,
                rx_bps: baseValue + Math.random() * 500000,
                tx_bps: baseValue,
                drops: Math.random() > 0.95 ? Math.floor(Math.random() * 10) : 0
            };


            this.listeners.forEach(cb => cb({ 'DEFAULT': stats }));
        }, 1000);
    }

    private stop() {
        console.log("[Simulator] Stopping traffic generation.");
        if (this.intervalId) {
            clearInterval(this.intervalId);
            this.intervalId = null;
        }
    }
}

export const trafficSimulator = new TrafficSimulator();
