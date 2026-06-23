package observability

import (
	"bufio"
	"io"
	"sync"
	"sync/atomic"
	"time"
)

const (
	asyncQueueSize   = 8192
	asyncBufSize     = 64 * 1024
	asyncFlushPeriod = 250 * time.Millisecond
)

// asyncWriter decouples log writes from the request path. Callers (the slog
// handler) enqueue a copy of each record and return immediately; a single
// background goroutine drains the queue through a bufio.Writer, so disk I/O and
// the underlying writer's lock never block request handling. When the queue is
// full (the writer can't keep up) records are dropped rather than blocking the
// request path; the dropped count is reported on Close.
type asyncWriter struct {
	underlying io.WriteCloser
	ch         chan []byte
	stop       chan struct{}
	done       chan struct{}
	stopOnce   sync.Once
	dropped    atomic.Uint64
}

var _ io.WriteCloser = (*asyncWriter)(nil)

func newAsyncWriter(underlying io.WriteCloser, queueSize int) *asyncWriter {
	if queueSize <= 0 {
		queueSize = asyncQueueSize
	}
	a := &asyncWriter{
		underlying: underlying,
		ch:         make(chan []byte, queueSize),
		stop:       make(chan struct{}),
		done:       make(chan struct{}),
	}
	go a.run()
	return a
}

// Write enqueues a copy of p. It never blocks: if the queue is full the record
// is dropped and counted. slog reuses p after Write returns, so it is copied.
func (a *asyncWriter) Write(p []byte) (int, error) {
	b := make([]byte, len(p))
	copy(b, p)
	select {
	case a.ch <- b:
	default:
		a.dropped.Add(1)
	}
	return len(p), nil
}

func (a *asyncWriter) run() {
	defer close(a.done)
	bw := bufio.NewWriterSize(a.underlying, asyncBufSize)
	ticker := time.NewTicker(asyncFlushPeriod)
	defer ticker.Stop()
	for {
		select {
		case b := <-a.ch:
			_, _ = bw.Write(b)
		case <-ticker.C:
			_ = bw.Flush()
		case <-a.stop:
			// Drain everything still queued, then flush and exit.
			for {
				select {
				case b := <-a.ch:
					_, _ = bw.Write(b)
				default:
					_ = bw.Flush()
					return
				}
			}
		}
	}
}

// Close stops the drain goroutine (flushing buffered records) and closes the
// underlying writer. Safe to call multiple times.
func (a *asyncWriter) Close() error {
	a.stopOnce.Do(func() { close(a.stop) })
	<-a.done
	return a.underlying.Close()
}

// Dropped returns the number of records dropped because the queue was full.
func (a *asyncWriter) Dropped() uint64 {
	return a.dropped.Load()
}
