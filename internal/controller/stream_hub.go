package controller

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"sync"

	"github.com/gorilla/websocket"
)

type TrafficUpdate struct {
	LinkUpdates map[string]LinkStatsData `json:"link_updates"`
}

type LinkStatsData struct {
	Timestamp int64   `json:"timestamp"`
	RxBps     float64 `json:"rx_bps"`
	TxBps     float64 `json:"tx_bps"`
	Drops     uint64  `json:"drops"`
}

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

type StreamHub struct {
	clients   map[*websocket.Conn]bool
	broadcast chan []byte
	mu        sync.Mutex
}

func NewStreamHub() *StreamHub {
	return &StreamHub{
		clients:   make(map[*websocket.Conn]bool),
		broadcast: make(chan []byte),
	}
}

func (h *StreamHub) Run() {
	for {
		message := <-h.broadcast
		h.mu.Lock()
		for client := range h.clients {
			err := client.WriteMessage(websocket.TextMessage, message)
			if err != nil {
				client.Close()
				delete(h.clients, client)
			}
		}
		h.mu.Unlock()
	}
}

func (h *StreamHub) BroadcastTraffic(data TrafficUpdate) {
	bytes, err := json.Marshal(data)
	if err != nil {
		slog.Error("Failed to marshal traffic data", "err", err)
		return
	}
	select {
	case h.broadcast <- bytes:
	default:
	}
}

func (h *StreamHub) HandleConnections(w http.ResponseWriter, r *http.Request) {
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		slog.Error("WebSocket upgrade failed", "err", err)
		return
	}
	defer ws.Close()

	h.mu.Lock()
	h.clients[ws] = true
	h.mu.Unlock()

	slog.Info("New frontend client connected")

	for {
		_, _, err := ws.ReadMessage()
		if err != nil {
			h.mu.Lock()
			delete(h.clients, ws)
			h.mu.Unlock()
			break
		}
	}
}
