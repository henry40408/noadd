package upstream

import "fmt"

// Strategy is how the forwarder orders the upstream servers.
type Strategy string

const (
	Sequential    Strategy = "sequential"
	RoundRobin    Strategy = "round-robin"
	LowestLatency Strategy = "lowest-latency"
)

// ParseStrategy parses the kebab-case name stored in settings.
func ParseStrategy(name string) (Strategy, error) {
	switch strategy := Strategy(name); strategy {
	case Sequential, RoundRobin, LowestLatency:
		return strategy, nil
	}
	return "", fmt.Errorf("unknown strategy: %s", name)
}

func (s Strategy) String() string { return string(s) }
