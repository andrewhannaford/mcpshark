// Package state manages mcpshark's persistent local state.
//
// State is stored in a SQLite database (pure-Go, no CGO) at
// ~/.mcpshark/state.db. It currently tracks:
//
//   - tools/list fingerprints per server identity, for drift detection
//   - session metadata for cross-session correlation
//   - anonymous drop counters for the /metrics endpoint
//
// The store is opened once at proxy startup and closed on graceful shutdown.
// Crash-safety is provided by SQLite's WAL mode.
//
// TODO(week4): implement actual store.
package state
