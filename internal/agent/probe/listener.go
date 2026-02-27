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
	ListenerPort = 9090
)

// Listener manages TCP echo servers inside Pod network namespaces.
// Each Pod gets its own goroutine running a TCP listener on port 9090.
type Listener struct {
	mu        sync.Mutex
	listeners map[string]context.CancelFunc // podName -> cancel function
}

func NewListener() *Listener {
	return &Listener{
		listeners: make(map[string]context.CancelFunc),
	}
}

// StartForPod starts a TCP listener on port 9090 inside the given Pod's netns.
// It is idempotent — calling it again for the same pod is a no-op.
func (l *Listener) StartForPod(podName string, handle netns.NsHandle) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if _, exists := l.listeners[podName]; exists {
		return nil // Already running
	}

	ctx, cancel := context.WithCancel(context.Background())
	l.listeners[podName] = cancel

	go l.runInNetns(ctx, podName, handle)

	return nil
}

// StopForPod stops the TCP listener for a given Pod.
func (l *Listener) StopForPod(podName string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if cancel, exists := l.listeners[podName]; exists {
		cancel()
		delete(l.listeners, podName)
		log.Printf("[ProbeListener] Stopped listener for pod %s", podName)
	}
}

// StopAll stops all active listeners.
func (l *Listener) StopAll() {
	l.mu.Lock()
	defer l.mu.Unlock()

	for name, cancel := range l.listeners {
		cancel()
		delete(l.listeners, name)
	}
	log.Println("[ProbeListener] All listeners stopped")
}

// runInNetns enters the Pod's network namespace and starts a TCP listener.
// IMPORTANT: This must lock the OS thread because network namespaces are per-thread in Linux.
func (l *Listener) runInNetns(ctx context.Context, podName string, targetNs netns.NsHandle) {
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
	addr := fmt.Sprintf(":%d", ListenerPort)
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

	log.Printf("[ProbeListener] Listening on :%d in pod %s netns", ListenerPort, podName)

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
				log.Printf("[ProbeListener] Accept error in pod %s: %v", podName, err)
				return
			}
		}
		// Close immediately — we only need the TCP handshake for RTT measurement
		conn.Close()
	}
}
