package core

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"sync"
)

type portPicker struct {
	mu         sync.Mutex
	start      int
	end        int
	randomized bool
	next       int
}

func newPortPicker(spec string) (*portPicker, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		spec = "0"
	}

	picker := &portPicker{}
	if strings.Contains(spec, "~") {
		parts := strings.Split(spec, "~")
		if len(parts) != 2 {
			return nil, errors.New("bindPort random range must be <port>~<port>")
		}
		start, end, err := parsePortRange(parts[0], parts[1])
		if err != nil {
			return nil, err
		}
		picker.start = start
		picker.end = end
		picker.randomized = true
		picker.next = start
		return picker, nil
	}

	if strings.Contains(spec, "-") {
		parts := strings.Split(spec, "-")
		if len(parts) != 2 {
			return nil, errors.New("bindPort sequential range must be <port>-<port>")
		}
		start, end, err := parsePortRange(parts[0], parts[1])
		if err != nil {
			return nil, err
		}
		picker.start = start
		picker.end = end
		picker.next = start
		return picker, nil
	}

	port, err := strconv.Atoi(spec)
	if err != nil || port < 0 || port > 65535 {
		return nil, fmt.Errorf("bindPort %q is invalid", spec)
	}
	picker.start = port
	picker.end = port
	picker.next = port
	return picker, nil
}

func parsePortRange(rawStart, rawEnd string) (int, int, error) {
	start, err := strconv.Atoi(strings.TrimSpace(rawStart))
	if err != nil {
		return 0, 0, fmt.Errorf("bindPort %q is invalid", rawStart)
	}
	end, err := strconv.Atoi(strings.TrimSpace(rawEnd))
	if err != nil {
		return 0, 0, fmt.Errorf("bindPort %q is invalid", rawEnd)
	}
	if start < 0 || end < 0 || start > 65535 || end > 65535 || start > end {
		return 0, 0, errors.New("bindPort range is invalid")
	}
	return start, end, nil
}

func (p *portPicker) Next() int {
	return p.NextExcept(-1)
}

func (p *portPicker) NextExcept(except int) int {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.start == p.end {
		return p.start
	}
	if p.randomized {
		size := p.end - p.start + 1
		for attempt := 0; attempt < size; attempt++ {
			n, err := rand.Int(rand.Reader, big.NewInt(int64(size)))
			if err != nil {
				break
			}
			port := p.start + int(n.Int64())
			if port != except {
				return port
			}
		}
		for port := p.start; port <= p.end; port++ {
			if port != except {
				return port
			}
		}
		return p.start
	}

	port := p.next
	p.next++
	if p.next > p.end {
		p.next = p.start
	}
	if port == except {
		port = p.next
		p.next++
		if p.next > p.end {
			p.next = p.start
		}
	}
	return port
}
