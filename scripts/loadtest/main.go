// Command loadtest is a small HTTP load generator for Relay. It fires requests
// at a target URL with a fixed concurrency for a duration and reports throughput,
// latency percentiles, status distribution and errors.
//
// Usage:
//
//	go run ./scripts/loadtest -url http://localhost:8088/your-route -c 50 -d 10s
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

func main() {
	var (
		url         string
		concurrency int
		duration    time.Duration
		timeout     time.Duration
		method      string
	)
	flag.StringVar(&url, "url", "http://localhost:8088/", "target URL")
	flag.IntVar(&concurrency, "c", 50, "number of concurrent workers")
	flag.DurationVar(&duration, "d", 10*time.Second, "test duration")
	flag.DurationVar(&timeout, "timeout", 5*time.Second, "per-request timeout")
	flag.StringVar(&method, "method", http.MethodGet, "HTTP method")
	flag.Parse()

	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			MaxIdleConns:        concurrency * 2,
			MaxIdleConnsPerHost: concurrency * 2,
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), duration)
	defer cancel()

	var (
		total   atomic.Int64
		errors  atomic.Int64
		statusM sync.Mutex
		status  = map[int]int64{}
		latM    sync.Mutex
		lat     []time.Duration
	)

	start := time.Now()
	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ctx.Err() == nil {
				reqStart := time.Now()
				req, err := http.NewRequestWithContext(ctx, method, url, nil)
				if err != nil {
					errors.Add(1)
					continue
				}
				resp, err := client.Do(req)
				elapsed := time.Since(reqStart)
				if err != nil {
					if ctx.Err() != nil {
						return
					}
					errors.Add(1)
					continue
				}
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()

				total.Add(1)
				statusM.Lock()
				status[resp.StatusCode]++
				statusM.Unlock()
				latM.Lock()
				lat = append(lat, elapsed)
				latM.Unlock()
			}
		}()
	}
	wg.Wait()
	wall := time.Since(start)

	n := total.Load()
	fmt.Printf("target:       %s\n", url)
	fmt.Printf("concurrency:  %d\n", concurrency)
	fmt.Printf("duration:     %s\n", wall.Round(time.Millisecond))
	fmt.Printf("requests:     %d\n", n)
	fmt.Printf("errors:       %d\n", errors.Load())
	if wall > 0 {
		fmt.Printf("throughput:   %.0f req/s\n", float64(n)/wall.Seconds())
	}
	if len(lat) > 0 {
		sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
		fmt.Printf("latency p50:  %s\n", pct(lat, 0.50).Round(time.Microsecond))
		fmt.Printf("latency p95:  %s\n", pct(lat, 0.95).Round(time.Microsecond))
		fmt.Printf("latency p99:  %s\n", pct(lat, 0.99).Round(time.Microsecond))
		fmt.Printf("latency max:  %s\n", lat[len(lat)-1].Round(time.Microsecond))
	}
	fmt.Println("status codes:")
	for code, count := range status {
		fmt.Printf("  %d: %d\n", code, count)
	}

	if errors.Load() > 0 {
		os.Exit(1)
	}
}

func pct(sorted []time.Duration, p float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	idx := int(p * float64(len(sorted)))
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}
