package discovery

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func TestClampTTL(t *testing.T) {
	t.Parallel()

	cases := []struct {
		ttl, refresh, min, max time.Duration
		want                   time.Duration
	}{
		{5 * time.Second, 30 * time.Second, time.Second, 0, 5 * time.Second},
		{0, 10 * time.Second, time.Second, 0, 10 * time.Second},
		{60 * time.Second, 15 * time.Second, time.Second, 0, 15 * time.Second},
		{100 * time.Millisecond, 30 * time.Second, time.Second, 0, time.Second},
		{30 * time.Second, 60 * time.Second, time.Second, 5 * time.Second, 5 * time.Second},
	}
	for _, tc := range cases {
		if got := ClampTTL(tc.ttl, tc.refresh, tc.min, tc.max); got != tc.want {
			t.Fatalf("ClampTTL(%v,%v,%v,%v)=%v want %v", tc.ttl, tc.refresh, tc.min, tc.max, got, tc.want)
		}
	}
}

func TestFakeResolverTTLAndQueue(t *testing.T) {
	t.Parallel()

	fake := &FakeResolver{}
	fake.Push(Result{
		TTL: 2 * time.Second,
		Endpoints: []Endpoint{
			{Host: "10.0.0.1", Port: 8080, Weight: 1},
		},
	})
	fake.Push(Result{
		TTL: 5 * time.Second,
		Endpoints: []Endpoint{
			{Host: "10.0.0.2", Port: 8080, Weight: 1},
			{Host: "10.0.0.3", Port: 8080, Weight: 1},
		},
	})

	first, err := fake.Resolve(context.Background(), Query{Name: "svc.local", RecordType: "A"})
	if err != nil {
		t.Fatalf("first Resolve: %v", err)
	}
	if first.TTL != 2*time.Second || len(first.Endpoints) != 1 || first.Endpoints[0].Host != "10.0.0.1" {
		t.Fatalf("unexpected first result: %+v", first)
	}

	second, err := fake.Resolve(context.Background(), Query{Name: "svc.local", RecordType: "A"})
	if err != nil {
		t.Fatalf("second Resolve: %v", err)
	}
	if second.TTL != 5*time.Second || len(second.Endpoints) != 2 {
		t.Fatalf("unexpected second result: %+v", second)
	}
	if got := len(fake.Calls()); got != 2 {
		t.Fatalf("calls = %d, want 2", got)
	}
}

func TestDNSResolverARecordWithTTL(t *testing.T) {
	t.Parallel()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	defer pc.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 1232)
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		var req dnsmessage.Message
		if err := req.Unpack(buf[:n]); err != nil {
			return
		}
		resp := dnsmessage.Message{
			Header: dnsmessage.Header{
				ID:                 req.ID,
				Response:           true,
				RecursionAvailable: true,
			},
			Questions: req.Questions,
			Answers: []dnsmessage.Resource{{
				Header: dnsmessage.ResourceHeader{
					Name:  req.Questions[0].Name,
					Type:  dnsmessage.TypeA,
					Class: dnsmessage.ClassINET,
					TTL:   7,
				},
				Body: &dnsmessage.AResource{A: [4]byte{10, 1, 2, 3}},
			}},
		}
		packed, err := resp.Pack()
		if err != nil {
			return
		}
		_, _ = pc.WriteTo(packed, addr)
	}()

	r := &DNSResolver{Nameservers: []string{pc.LocalAddr().String()}}
	res, err := r.Resolve(context.Background(), Query{Name: "orders.svc.local", RecordType: "A"})
	wg.Wait()
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if res.TTL != 7*time.Second {
		t.Fatalf("TTL = %v, want 7s", res.TTL)
	}
	if len(res.Endpoints) != 1 || res.Endpoints[0].Host != "10.1.2.3" {
		t.Fatalf("endpoints = %+v", res.Endpoints)
	}
}

func TestDNSResolverSRV(t *testing.T) {
	t.Parallel()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	defer pc.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 1232)
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		var req dnsmessage.Message
		if err := req.Unpack(buf[:n]); err != nil {
			return
		}
		target, err := dnsmessage.NewName("pod-a.orders.svc.local.")
		if err != nil {
			return
		}
		resp := dnsmessage.Message{
			Header: dnsmessage.Header{
				ID:                 req.ID,
				Response:           true,
				RecursionAvailable: true,
			},
			Questions: req.Questions,
			Answers: []dnsmessage.Resource{{
				Header: dnsmessage.ResourceHeader{
					Name:  req.Questions[0].Name,
					Type:  dnsmessage.TypeSRV,
					Class: dnsmessage.ClassINET,
					TTL:   11,
				},
				Body: &dnsmessage.SRVResource{
					Priority: 0,
					Weight:   10,
					Port:     8443,
					Target:   target,
				},
			}},
		}
		packed, err := resp.Pack()
		if err != nil {
			return
		}
		_, _ = pc.WriteTo(packed, addr)
	}()

	r := &DNSResolver{Nameservers: []string{pc.LocalAddr().String()}}
	res, err := r.Resolve(context.Background(), Query{
		Name:       "_https._tcp.orders.svc.local",
		RecordType: "SRV",
	})
	<-done
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if res.TTL != 11*time.Second {
		t.Fatalf("TTL = %v, want 11s", res.TTL)
	}
	if len(res.Endpoints) != 1 {
		t.Fatalf("endpoints = %+v", res.Endpoints)
	}
	ep := res.Endpoints[0]
	if ep.Host != "pod-a.orders.svc.local" || ep.Port != 8443 || ep.Weight != 10 {
		t.Fatalf("endpoint = %+v", ep)
	}
}

func TestParseResolvConf(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "resolv.conf")
	content := "# comment\nnameserver 1.1.1.1\nnameserver 8.8.8.8\noptions ndots:1\n"
	if err := writeFile(path, content); err != nil {
		t.Fatal(err)
	}
	servers, err := parseResolvConf(path)
	if err != nil {
		t.Fatalf("parseResolvConf: %v", err)
	}
	if len(servers) != 2 || servers[0] != "1.1.1.1:53" || servers[1] != "8.8.8.8:53" {
		t.Fatalf("servers = %v", servers)
	}
}

func writeFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o600)
}
