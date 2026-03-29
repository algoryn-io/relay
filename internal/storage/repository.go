package storage

import (
	"context"
	"time"
)

type Repository struct {
	store *Store
}

type RequestRecord struct {
	ID        int64
	Timestamp time.Time
	Method    string
	Path      string
	Status    int
	LatencyMs int64
	BackendID string
	ClientIP  string
	RouteID   string
}

type MetricSummaryRow struct {
	RouteID      string
	WindowStart  time.Time
	WindowSecs   int
	SnapshotJSON []byte
	UpdatedAt    time.Time
}

type BackendRow struct {
	ID        string
	URL       string
	Healthy   bool
	LastCheck time.Time
}

func NewRepository(s *Store) *Repository {
	return &Repository{store: s}
}

func (r *Repository) InsertRequest(ctx context.Context, req RequestRecord) error {
	_, _ = ctx, req
	// TODO: implement INSERT for request telemetry rows into requests table.
	return nil
}

func (r *Repository) UpsertMetricsSummary(ctx context.Context, routeID string, windowStart time.Time, windowSecs int, snapshotJSON []byte) error {
	_, _, _, _, _ = ctx, routeID, windowStart, windowSecs, snapshotJSON
	// TODO: implement UPSERT for route-level metrics snapshots into metrics_summary.
	return nil
}

func (r *Repository) UpsertBackendHealth(ctx context.Context, id, url string, healthy bool) error {
	_, _, _, _ = ctx, id, url, healthy
	// TODO: implement UPSERT for backend health state in backends table.
	return nil
}

func (r *Repository) QueryMetricsSummary(ctx context.Context, routeID string, limit int) ([]MetricSummaryRow, error) {
	_, _, _ = ctx, routeID, limit
	// TODO: implement SELECT of recent metrics snapshots ordered by newest window.
	return []MetricSummaryRow{}, nil
}

func (r *Repository) QueryRecentRequests(ctx context.Context, limit int) ([]RequestRecord, error) {
	_, _ = ctx, limit
	// TODO: implement SELECT of latest request records with bounded result size.
	return []RequestRecord{}, nil
}

func (r *Repository) QueryBackends(ctx context.Context) ([]BackendRow, error) {
	_ = ctx
	// TODO: implement SELECT of current backend health rows for dashboard rendering.
	return []BackendRow{}, nil
}
