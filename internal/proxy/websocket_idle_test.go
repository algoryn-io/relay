package proxy

import (
	"errors"
	"net"
	"os"
	"testing"
	"time"
)

// idleConn must close out a read when the peer is silent past the idle window,
// so a dead/NATed client cannot hold a tunnel open forever.
func TestIdleConnTimesOutSilentRead(t *testing.T) {
	t.Parallel()

	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	ic := &idleConn{Conn: c1, idle: 20 * time.Millisecond}

	done := make(chan error, 1)
	go func() {
		buf := make([]byte, 8)
		_, err := ic.Read(buf) // no writer on c2 → must hit the idle deadline
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Read returned nil error, want idle timeout")
		}
		var netErr net.Error
		if !errors.As(err, &netErr) || !netErr.Timeout() {
			if !errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatalf("err = %v, want a timeout error", err)
			}
		}
	case <-time.After(time.Second):
		t.Fatal("Read did not time out within 1s")
	}
}
