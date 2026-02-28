package probe

import (
	"context"
	"fmt"
	"log"
	"net"
	"runtime"
	"sync"

	"github.com/vishvananda/netns"
)

const (
	SimListenerPort = 9090
	SysListenerPort = 9100
)

// Listener manages TCP accept servers inside Pod network namespaces.
// Each Pod can have listeners on multiple ports (SIM on 9090, SYS on 9100).
type Listener struct {
	mu        sync.Mutex
	listeners map[string]context.CancelFunc // "podName:port" -> cancel function
}

func NewListener() *Listener {
	return &Listener{
		listeners: make(map[string]context.CancelFunc),
	}
}

// listenerKey returns a unique key for a pod+port combination.
func listenerKey(podName string, port int) string {
	return fmt.Sprintf("%s:%d", podName, port)
}

// StartForPod starts a TCP listener on the given port inside the Pod's netns.
// It is idempotent — calling it again for the same pod+port is a no-op.
func (l *Listener) StartForPod(podName string, port int, handle netns.NsHandle) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	key := listenerKey(podName, port)
	if _, exists := l.listeners[key]; exists {
		return nil // Already running
	}

	ctx, cancel := context.WithCancel(context.Background())
	l.listeners[key] = cancel

	go l.runInNetns(ctx, podName, port, handle)

	return nil
}

// StopForPod stops all TCP listeners for a given Pod.
func (l *Listener) StopForPod(podName string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	for key, cancel := range l.listeners {
		// Keys are "podName:port" — match prefix
		if len(key) > len(podName) && key[:len(podName)+1] == podName+":" {
			cancel()
			delete(l.listeners, key)
			log.Printf("[ProbeListener] Stopped listener %s", key)
		}
	}
}

// StopAll stops all active listeners.
func (l *Listener) StopAll() {
	l.mu.Lock()
	defer l.mu.Unlock()

	for key, cancel := range l.listeners {
		cancel()
		delete(l.listeners, key)
	}
	log.Println("[ProbeListener] All listeners stopped")
}

// runInNetns enters the Pod's network namespace and starts a TCP listener.
// IMPORTANT: This must lock the OS thread because network namespaces are per-thread in Linux.
func (l *Listener) runInNetns(ctx context.Context, podName string, port int, targetNs netns.NsHandle) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Save host netns to restore later
	hostNs, err := netns.Get()
	if err != nil {
		log.Printf("[ProbeListener] ERROR: Failed to get host netns: %v", err)
		return
	}
	defer hostNs.Close()

	// Enter Pod's netns
	if err := netns.Set(targetNs); err != nil {
		log.Printf("[ProbeListener] ERROR: Failed to enter netns for pod %s: %v", podName, err)
		return
	}

	// Start listener INSIDE Pod netns
	addr := fmt.Sprintf(":%d", port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Printf("[ProbeListener] ERROR: Failed to listen on %s in pod %s netns: %v", addr, podName, err)
		// Restore host netns before returning
		netns.Set(hostNs)
		return
	}

	// Restore host netns — the listener fd is already bound to the pod netns
	if err := netns.Set(hostNs); err != nil {
		log.Printf("[ProbeListener] ERROR: Failed to restore host netns: %v", err)
		ln.Close()
		return
	}

	log.Printf("[ProbeListener] Listening on :%d in pod %s netns", port, podName)

	// Accept loop — close connections immediately (we only need TCP handshake)
	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return // Normal shutdown
			default:
				log.Printf("[ProbeListener] Accept error in pod %s port %d: %v", podName, port, err)
				return
			}
		}
		// Close immediately — we only need the TCP handshake for RTT measurement
		conn.Close()
	}
}
