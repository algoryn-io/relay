package observability

import (
	"bytes"
	"sync"
	"testing"
)

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) Close() error { return nil }

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func TestAsyncWriterFlushesOnClose(t *testing.T) {
	t.Parallel()

	under := &syncBuffer{}
	a := newAsyncWriter(under, 16)

	for i := 0; i < 5; i++ {
		if _, err := a.Write([]byte("line\n")); err != nil {
			t.Fatalf("Write() error = %v", err)
		}
	}
	// Close must flush everything queued.
	if err := a.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	if got := under.String(); got != "line\nline\nline\nline\nline\n" {
		t.Fatalf("flushed = %q, want 5 lines", got)
	}
}

func TestAsyncWriterWriteDoesNotBlockAndCopies(t *testing.T) {
	t.Parallel()

	under := &syncBuffer{}
	a := newAsyncWriter(under, 4)
	t.Cleanup(func() { _ = a.Close() })

	// Mutating the caller's buffer after Write must not corrupt the record.
	p := []byte("abc\n")
	if _, err := a.Write(p); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	copy(p, []byte("XYZ\n"))

	_ = a.Close()
	if got := under.String(); got != "abc\n" {
		t.Fatalf("record = %q, want abc (Write must copy)", got)
	}
}
