package proxy

import "sync/atomic"

type Balancer interface {
	Pick(instances []*Instance) *Instance
}

type RoundRobin struct {
	next atomic.Int64
}

var _ Balancer = (*RoundRobin)(nil)

func NewRoundRobin() *RoundRobin {
	return &RoundRobin{}
}

func (r *RoundRobin) Pick(instances []*Instance) *Instance {
	if len(instances) == 0 {
		return nil
	}
	// TODO: implement full round-robin selection honoring health and routing policy.
	idx := r.next.Add(1)
	return instances[int(idx-1)%len(instances)]
}

type LeastConnections struct{}

var _ Balancer = (*LeastConnections)(nil)

func NewLeastConnections() *LeastConnections {
	return &LeastConnections{}
}

func (l *LeastConnections) Pick(instances []*Instance) *Instance {
	_ = l
	if len(instances) == 0 {
		return nil
	}
	// TODO: implement least-connections balancing using ActiveConns across healthy backends.
	return instances[0]
}
