package bpf

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
)

// Logger is an independent BPF log reader that consumes log messages
// from the kernel via ringbuf and outputs them to the configured writer.
type Logger struct {
	reader *ringbuf.Reader
	output io.Writer
	done   chan struct{}
}

// NewLogger creates a log reader from the ringbuf map.
// If output is nil, os.Stdout is used.
func NewLogger(ringbufMap *ebpf.Map, output io.Writer) (*Logger, error) {
	reader, err := ringbuf.NewReader(ringbufMap)
	if err != nil {
		return nil, fmt.Errorf("create ringbuf reader: %w", err)
	}

	if output == nil {
		output = os.Stdout
	}

	return &Logger{
		reader: reader,
		output: output,
		done:   make(chan struct{}),
	}, nil
}

// Start begins consuming log messages in a background goroutine.
func (l *Logger) Start() {
	go func() {
		for {
			select {
			case <-l.done:
				return
			default:
				record, err := l.reader.Read()
				if err != nil {
					if errors.Is(err, ringbuf.ErrClosed) {
						return
					}
					continue
				}

				// Output formatted string directly from kernel
				msg := bytes.TrimRight(record.RawSample, "\x00")
				fmt.Fprintf(l.output, "%s\n", msg)
			}
		}
	}()
}

// Stop closes the log reader and stops the background goroutine.
func (l *Logger) Stop() {
	close(l.done)
	l.reader.Close()
}
