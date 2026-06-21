package admin

import (
	"encoding/json"
	"net"
	"net/http"
	"strings"

	"algoryn.io/relay/internal/config"
	"algoryn.io/relay/internal/httpx"
	"algoryn.io/relay/internal/proxy"
)

const pathPrefix = "/_relay/admin"

// Handler serves the /_relay/admin/* management endpoints.
// All endpoints require the client IP to be in the configured allowlist.
type Handler struct {
	px          *proxy.Proxy
	routes      map[string]config.RouteRuntime
	allowedNets []*net.IPNet
}

// New builds an admin Handler. allowedCIDRs restricts access by IP range;
// if empty, only loopback addresses are allowed.
func New(px *proxy.Proxy, routes map[string]config.RouteRuntime, allowedCIDRs []string) *Handler {
	nets := httpx.ParseTrustedNets(allowedCIDRs)
	if len(nets) == 0 {
		_, lo4, _ := net.ParseCIDR("127.0.0.0/8")
		_, lo6, _ := net.ParseCIDR("::1/128")
		nets = []*net.IPNet{lo4, lo6}
	}
	return &Handler{px: px, routes: routes, allowedNets: nets}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	clientIP := net.ParseIP(httpx.ClientIP(r))
	if clientIP == nil || !h.ipAllowed(clientIP) {
		httpx.WriteError(w, http.StatusForbidden, "forbidden")
		return
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

func (h *Handler) ipAllowed(ip net.IP) bool {
	for _, n := range h.allowedNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
