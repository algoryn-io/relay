package observability

import (
	"embed"
	"encoding/json"
	"net/http"

	"algoryn.io/relay/internal/storage"
)

type Dashboard struct {
	mux    *http.ServeMux
	repo   *storage.Repository
	assets embed.FS
}

var _ http.Handler = (*Dashboard)(nil)

func NewDashboard(repo *storage.Repository, assets embed.FS) *Dashboard {
	d := &Dashboard{
		mux:    http.NewServeMux(),
		repo:   repo,
		assets: assets,
	}

	d.mux.HandleFunc("GET /api/metrics/summary", d.handleMetricsSummary)
	d.mux.HandleFunc("GET /api/metrics/requests", d.handleMetricsRequests)
	d.mux.HandleFunc("GET /api/backends", d.handleBackends)
	d.mux.HandleFunc("GET /api/logs", d.handleLogs)

	return d
}

func (d *Dashboard) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	d.mux.ServeHTTP(w, r)
}

func (d *Dashboard) handleMetricsSummary(w http.ResponseWriter, r *http.Request) {
	_, _ = d, r
	writeEmptyArray(w)
}

func (d *Dashboard) handleMetricsRequests(w http.ResponseWriter, r *http.Request) {
	_, _ = d, r
	writeEmptyArray(w)
}

func (d *Dashboard) handleBackends(w http.ResponseWriter, r *http.Request) {
	_, _ = d, r
	writeEmptyArray(w)
}

func (d *Dashboard) handleLogs(w http.ResponseWriter, r *http.Request) {
	_, _ = d, r
	writeEmptyArray(w)
}

func writeEmptyArray(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode([]any{})
}
