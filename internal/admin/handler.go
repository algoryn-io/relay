package admin

import (
	"crypto/subtle"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"strings"

	"algoryn.io/relay/internal/config"
	"algoryn.io/relay/internal/httpx"
	"algoryn.io/relay/internal/proxy"
)

const pathPrefix = "/_relay/admin"

// Handler serves the /_relay/admin/* management endpoints.
// All endpoints require the client IP to be in the configured allowlist, and,
// when a token is configured, a matching bearer token.
type Handler struct {
	px        *proxy.Proxy
	routes    map[string]config.RouteRuntime
	access    *AccessControl
	readiness config.ReadinessPolicyConfig
	logger    *slog.Logger
}

// AccessControl is the shared real-peer CIDR and bearer-token gate used by
// admin and health endpoints. Forwarding headers are deliberately ignored.
type AccessControl struct {
	allowedNets []*net.IPNet
	token       string
	public      bool
}

// NewAccessControl builds an endpoint access gate. With publicDefault true, an
// empty CIDR list permits every real peer; otherwise it permits loopback only.
func NewAccessControl(allowedCIDRs []string, token string, publicDefault bool) *AccessControl {
	nets := httpx.ParseTrustedNets(allowedCIDRs)
	public := publicDefault && len(allowedCIDRs) == 0
	if !public && len(nets) == 0 {
		_, lo4, _ := net.ParseCIDR("127.0.0.0/8")
		_, lo6, _ := net.ParseCIDR("::1/128")
		nets = []*net.IPNet{lo4, lo6}
	}
	return &AccessControl{allowedNets: nets, token: strings.TrimSpace(token), public: public}
}

// New builds an admin Handler. allowedCIDRs restricts access by IP range;
// if empty, only loopback addresses are allowed. token, when non-empty, is
// required as an "Authorization: Bearer <token>" header. logger, when non-nil,
// receives audit entries for admin access and mutations.
func New(px *proxy.Proxy, routes map[string]config.RouteRuntime, allowedCIDRs []string, token string, logger *slog.Logger) *Handler {
	return NewWithReadiness(px, routes, allowedCIDRs, token, config.ReadinessPolicyConfig{}, logger)
}

// NewWithReadiness builds an admin handler with the configured readiness policy
// exposed through its authenticated diagnostic endpoint.
func NewWithReadiness(
	px *proxy.Proxy,
	routes map[string]config.RouteRuntime,
	allowedCIDRs []string,
	token string,
	readiness config.ReadinessPolicyConfig,
	logger *slog.Logger,
) *Handler {
	return &Handler{
		px: px, routes: routes,
		access:    NewAccessControl(allowedCIDRs, token, false),
		readiness: readiness, logger: logger,
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Gate on the real TCP peer (RemoteAddr), not the forwarded client IP, so the
	// allowlist cannot be bypassed by spoofing X-Forwarded-For.
	peer := httpx.PeerIP(r)
	if status := h.access.Status(r); status == http.StatusForbidden {
		h.audit("admin access denied (ip)", peer, r)
		httpx.WriteError(w, http.StatusForbidden, "forbidden")
		return
	} else if status == http.StatusUnauthorized {
		h.audit("admin access denied (token)", peer, r)
		httpx.WriteError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	// Audit every state-changing call with the resolved peer.
	if r.Method != http.MethodGet {
		h.audit("admin action", peer, r)
	}

	// Strip the fixed prefix and split into path segments.
	sub := strings.TrimPrefix(r.URL.Path, pathPrefix)
	sub = strings.TrimPrefix(sub, "/")
	parts := strings.SplitN(sub, "/", 4)

	switch {
	case len(parts) >= 1 && parts[0] == "backends":
		h.handleBackends(w, r, parts[1:])

	case len(parts) == 1 && parts[0] == "routes" && r.Method == http.MethodGet:
		h.listRoutes(w)

	case len(parts) >= 1 && parts[0] == "circuit-breakers":
		h.handleCircuits(w, r, parts[1:])

	case len(parts) == 1 && (parts[0] == "readiness" || parts[0] == "ready") && r.Method == http.MethodGet:
		evaluation := h.px.EvaluateReadiness(h.readiness)
		status := "not_ready"
		if evaluation.Ready {
			status = "ready"
		}
		writeJSON(w, map[string]any{"status": status, "detail": evaluation})

	default:
		httpx.WriteError(w, http.StatusNotFound, "not_found")
	}
}

// ── /backends ─────────────────────────────────────────────────────────────────

func (h *Handler) handleBackends(w http.ResponseWriter, r *http.Request, parts []string) {
	switch {
	// GET /backends
	case len(parts) == 0 && r.Method == http.MethodGet:
		writeJSON(w, map[string]any{"backends": h.px.BackendSnapshots()})

	// GET /backends/{name}
	case len(parts) == 1 && r.Method == http.MethodGet:
		snap, ok := h.px.BackendSnapshot(parts[0])
		if !ok {
			httpx.WriteError(w, http.StatusNotFound, "backend_not_found")
			return
		}
		writeJSON(w, snap)

	// POST /backends/{name}/drain?instance=URL
	case len(parts) == 2 && parts[1] == "drain" && r.Method == http.MethodPost:
		instanceURL := r.URL.Query().Get("instance")
		if instanceURL == "" {
			httpx.WriteError(w, http.StatusBadRequest, "missing_instance_param")
			return
		}
		if err := h.px.DrainInstance(parts[0], instanceURL); err != nil {
			httpx.WriteError(w, http.StatusNotFound, err.Error())
			return
		}
		writeJSON(w, map[string]any{"drained": true, "backend": parts[0], "instance": instanceURL})

	default:
		httpx.WriteError(w, http.StatusNotFound, "not_found")
	}
}

// ── /routes ───────────────────────────────────────────────────────────────────

type routeResponse struct {
	Name        string   `json:"name"`
	Path        string   `json:"path,omitempty"`
	PathPrefix  string   `json:"path_prefix,omitempty"`
	Methods     []string `json:"methods"`
	Backend     string   `json:"backend"`
	StripPrefix string   `json:"strip_prefix,omitempty"`
}

func (h *Handler) listRoutes(w http.ResponseWriter) {
	routes := make([]routeResponse, 0, len(h.routes))
	for _, rt := range h.routes {
		routes = append(routes, routeResponse{
			Name:        rt.Name,
			Path:        rt.Path,
			PathPrefix:  rt.PathPrefix,
			Methods:     rt.Methods,
			Backend:     rt.BackendName,
			StripPrefix: rt.StripPrefix,
		})
	}
	writeJSON(w, map[string]any{"routes": routes})
}

// ── /circuit-breakers ─────────────────────────────────────────────────────────

type circuitResponse struct {
	Backend  string `json:"backend"`
	Instance string `json:"instance"`
	State    string `json:"state"`
}

func (h *Handler) handleCircuits(w http.ResponseWriter, r *http.Request, parts []string) {
	switch {
	// GET /circuit-breakers
	case len(parts) == 0 && r.Method == http.MethodGet:
		var circuits []circuitResponse
		for _, b := range h.px.BackendSnapshots() {
			for _, inst := range b.Instances {
				if inst.CircuitState != "" {
					circuits = append(circuits, circuitResponse{
						Backend:  b.Name,
						Instance: inst.URL,
						State:    inst.CircuitState,
					})
				}
			}
		}
		if circuits == nil {
			circuits = []circuitResponse{}
		}
		writeJSON(w, map[string]any{"circuit_breakers": circuits})

	// POST /circuit-breakers/{backend}/reset?instance=URL
	case len(parts) == 2 && parts[1] == "reset" && r.Method == http.MethodPost:
		instanceURL := r.URL.Query().Get("instance")
		if instanceURL == "" {
			httpx.WriteError(w, http.StatusBadRequest, "missing_instance_param")
			return
		}
		if err := h.px.ResetCircuit(parts[0], instanceURL); err != nil {
			httpx.WriteError(w, http.StatusNotFound, err.Error())
			return
		}
		writeJSON(w, map[string]any{"reset": true, "backend": parts[0], "instance": instanceURL})

	default:
		httpx.WriteError(w, http.StatusNotFound, "not_found")
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

// Status returns 0 when access is allowed, otherwise the HTTP rejection status.
func (a *AccessControl) Status(r *http.Request) int {
	peerIP := net.ParseIP(httpx.PeerIP(r))
	if peerIP == nil || !a.ipAllowed(peerIP) {
		return http.StatusForbidden
	}
	if !a.tokenOK(r) {
		return http.StatusUnauthorized
	}
	return 0
}

func (a *AccessControl) ipAllowed(ip net.IP) bool {
	if a.public {
		return true
	}
	for _, n := range a.allowedNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// tokenOK reports whether the request carries the configured bearer token.
// When no token is configured, access is permitted (IP-allowlist only).
func (a *AccessControl) tokenOK(r *http.Request) bool {
	if a.token == "" {
		return true
	}
	const prefix = "Bearer "
	raw := r.Header.Get("Authorization")
	if len(raw) <= len(prefix) || !strings.EqualFold(raw[:len(prefix)], prefix) {
		return false
	}
	got := strings.TrimSpace(raw[len(prefix):])
	return subtle.ConstantTimeCompare([]byte(got), []byte(a.token)) == 1
}

func (h *Handler) audit(msg, peer string, r *http.Request) {
	if h.logger == nil {
		return
	}
	h.logger.Info(msg,
		"event", "admin_audit",
		"peer", peer,
		"method", r.Method,
		"path", r.URL.Path,
	)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
