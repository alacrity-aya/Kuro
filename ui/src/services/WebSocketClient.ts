// src/services/WebSocketClient.ts
import type { TrafficStats } from '../types';


type BackendLinkStats = {
    timestamp: number;
    rx_bps: number;
    tx_bps: number;
    drops: number;
};

type TrafficUpdateMessage = {
    link_updates: Record<string, BackendLinkStats>;
};

type Callback = (data: Record<string, TrafficStats>) => void;

export class WebSocketClient {
    private ws: WebSocket | null = null;
    private url: string;
    private callback: Callback | null = null;
    private shouldReconnect = false;
    private retryCount = 0;

    constructor(url: string) {
        this.url = url;
    }

    connect(onData: Callback) {
        this.callback = onData;
        this.shouldReconnect = true;
        this.initWs();
    }

    private initWs() {
        console.log(`[WS] Connecting to ${this.url}...`);
        this.ws = new WebSocket(this.url);

        this.ws.onopen = () => {
            console.log("✅ [WS] Connected");
            this.retryCount = 0;
        };

        this.ws.onmessage = (event) => {
            try {
                const parsed: TrafficUpdateMessage = JSON.parse(event.data);

                if (this.callback && parsed.link_updates) {

                    const formatted: Record<string, TrafficStats> = {};

                    Object.entries(parsed.link_updates).forEach(([linkId, stats]) => {
                        formatted[linkId] = {
                            timestamp: stats.timestamp,
                            rx_bps: stats.rx_bps,
                            tx_bps: stats.tx_bps,
                            drops: stats.drops
                        };
                    });

                    this.callback(formatted);
                }
            } catch (e) {
                console.error("[WS] Parse error:", e);
            }
        };

        this.ws.onclose = () => {
            if (this.shouldReconnect) {
                const delay = Math.min(1000 * (2 ** this.retryCount), 10000);
                console.log(`❌ [WS] Disconnected. Retrying in ${delay}ms...`);
                setTimeout(() => {
                    this.retryCount++;
                    this.initWs();
                }, delay);
            } else {
                console.log("⏹️ [WS] Connection closed cleanly.");
            }
        };

        this.ws.onerror = (err) => {
            console.error("[WS] Error:", err);
            this.ws?.close();
        };
    }

    disconnect() {
        this.shouldReconnect = false;
        this.callback = null;
        this.ws?.close();
        this.ws = null;
    }
}


export const wsClient = new WebSocketClient('ws://localhost:8081/ws/traffic');
