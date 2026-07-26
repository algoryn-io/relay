package discovery

import (
	"context"
	"fmt"
	"sync"
)

// FakeResolver is an injectable resolver for unit tests. It returns scripted
// results (including TTL) and records every Resolve call.
type FakeResolver struct {
	mu sync.Mutex

	// Next is returned by the next Resolve call, then cleared. Prefer Set/Push
	// helpers for multi-step scripts.
	Next *Result
	// Err is returned when Next is nil and the name has no scripted result.
	Err error

	results map[string]Result
	queue   []Result
	calls   []Query
	hook    func(Query)
}

// Set installs a stable result for a name/type pair.
func (f *FakeResolver) Set(name, recordType string, result Result) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.results == nil {
		f.results = make(map[string]Result)
	}
	key, _ := NormalizeRecordType(recordType)
	f.results[fakeKey(name, key)] = result
}

// Push enqueues a one-shot result consumed by the next Resolve call (FIFO).
func (f *FakeResolver) Push(result Result) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.queue = append(f.queue, result)
}

// SetError configures a sticky error returned when no result is available.
func (f *FakeResolver) SetError(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Err = err
}

// OnResolve registers a hook invoked on every Resolve (after the call is recorded).
func (f *FakeResolver) OnResolve(fn func(Query)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.hook = fn
}

// Calls returns a copy of recorded queries.
func (f *FakeResolver) Calls() []Query {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]Query, len(f.calls))
	copy(out, f.calls)
	return out
}

// Resolve implements Resolver.
func (f *FakeResolver) Resolve(_ context.Context, q Query) (Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	recordType, err := NormalizeRecordType(q.RecordType)
	if err != nil {
		return Result{}, err
	}
	q.RecordType = recordType
	f.calls = append(f.calls, q)
	hook := f.hook

	if len(f.queue) > 0 {
		res := f.queue[0]
		f.queue = f.queue[1:]
		if hook != nil {
			// Unlock is not needed: hook runs under lock; keep hooks light.
			hook(q)
		}
		return cloneResult(res), nil
	}
	if f.Next != nil {
		res := *f.Next
		f.Next = nil
		if hook != nil {
			hook(q)
		}
		return cloneResult(res), nil
	}
	if f.results != nil {
		if res, ok := f.results[fakeKey(q.Name, recordType)]; ok {
			if hook != nil {
				hook(q)
			}
			return cloneResult(res), nil
		}
	}
	if f.Err != nil {
		if hook != nil {
			hook(q)
		}
		return Result{}, f.Err
	}
	if hook != nil {
		hook(q)
	}
	return Result{}, fmt.Errorf("fake resolver: no result for %s %s", recordType, q.Name)
}

func fakeKey(name, recordType string) string {
	return recordType + ":" + name
}

func cloneResult(in Result) Result {
	out := Result{TTL: in.TTL}
	if len(in.Endpoints) > 0 {
		out.Endpoints = append([]Endpoint(nil), in.Endpoints...)
	}
	return out
}
