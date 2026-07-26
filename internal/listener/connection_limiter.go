package listener

import (
	"net"
	"net/http"
	"sync"

	"algoryn.io/relay/internal/observability"
)

// connectionLimiter enforces a process-local limit by the real TCP peer IP.
// It tracks only live accepted connections and deletes an IP as soon as its
// final connection closes, so memory is bounded by current connection
// cardinality rather than every IP ever observed.
type connectionLimiter struct {
	mu          sync.Mutex
	limit       int
	byIP        map[string]int
	connections map[net.Conn]string
	metrics     *observability.PrometheusCollector
}

func newConnectionLimiter(limit int) *connectionLimiter {
	return &connectionLimiter{
		limit:       limit,
		byIP:        make(map[string]int),
		connections: make(map[net.Conn]string),
	}
}

// connState is installed directly on http.Server. ConnState runs before an HTTP
// request exists, so only conn.RemoteAddr (never X-Forwarded-For) is available.
func (l *connectionLimiter) connState(conn net.Conn, state http.ConnState) {
	switch state {
	case http.StateNew:
		l.add(conn)
	case http.StateClosed, http.StateHijacked:
		l.remove(conn)
	}
}

func (l *connectionLimiter) add(conn net.Conn) {
	ip, ok := peerIP(conn.RemoteAddr())
	if !ok {
		// A net.Listener accepted this connection, so a malformed RemoteAddr is
		// unexpected. Do not merge unknown peers into one synthetic identity.
		return
	}

	l.mu.Lock()
	if _, exists := l.connections[conn]; exists {
		l.mu.Unlock()
		return
	}
	if l.limit > 0 && l.byIP[ip] >= l.limit {
		metrics := l.metrics
		l.mu.Unlock()
		metrics.RecordListenerConnectionRejected()
		_ = conn.Close()
		return
	}

	l.connections[conn] = ip
	l.byIP[ip]++
	l.updateMetricsLocked()
	l.mu.Unlock()
}

func (l *connectionLimiter) remove(conn net.Conn) {
	l.mu.Lock()
	ip, ok := l.connections[conn]
	if !ok {
		l.mu.Unlock()
		return
	}
	delete(l.connections, conn)
	if l.byIP[ip] <= 1 {
		delete(l.byIP, ip)
	} else {
		l.byIP[ip]--
	}
	l.updateMetricsLocked()
	l.mu.Unlock()
}

func (l *connectionLimiter) setLimit(limit int) {
	l.mu.Lock()
	l.limit = limit
	l.mu.Unlock()
}

func (l *connectionLimiter) setMetrics(metrics *observability.PrometheusCollector) {
	l.mu.Lock()
	l.metrics = metrics
	l.updateMetricsLocked()
	l.mu.Unlock()
}

func (l *connectionLimiter) updateMetricsLocked() {
	l.metrics.SetListenerConnections(len(l.connections), len(l.byIP))
}

func peerIP(addr net.Addr) (string, bool) {
	if addr == nil {
		return "", false
	}
	if tcpAddr, ok := addr.(*net.TCPAddr); ok && tcpAddr.IP != nil {
		return tcpAddr.IP.String(), true
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return "", false
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return "", false
	}
	return ip.String(), true
}
