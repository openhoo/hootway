package gateway

import (
	"sync"
	"time"
)

// Event is one gateway request as shown in the console. It never contains
// key values, credentials, query strings or bodies.
type Event struct {
	Seq        uint64    `json:"seq"`
	Time       time.Time `json:"time"`
	Key        string    `json:"key"`
	Upstream   string    `json:"upstream"`
	Method     string    `json:"method"`
	Path       string    `json:"path"`
	Status     int       `json:"status"`
	Outcome    string    `json:"outcome"`
	DurationMS int64     `json:"duration_ms"`
}

// KeyStats aggregates requests per key since start.
type KeyStats struct {
	Forwarded int64      `json:"forwarded"`
	Denied    int64      `json:"denied"`
	LastUsed  *time.Time `json:"last_used,omitempty"`
}

type eventLog struct {
	mu    sync.Mutex
	buf   []Event
	next  int
	full  bool
	seq   uint64
	stats map[string]*KeyStats
	total struct{ forwarded, denied int64 }
}

func newEventLog(n int) *eventLog {
	return &eventLog{buf: make([]Event, n), stats: map[string]*KeyStats{}}
}

func (l *eventLog) add(e Event) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.seq++
	e.Seq = l.seq
	l.buf[l.next] = e
	l.next = (l.next + 1) % len(l.buf)
	if l.next == 0 {
		l.full = true
	}
	forwarded := e.Outcome == "forwarded"
	if forwarded {
		l.total.forwarded++
	} else {
		l.total.denied++
	}
	if e.Key == "" {
		return
	}
	s := l.stats[e.Key]
	if s == nil {
		s = &KeyStats{}
		l.stats[e.Key] = s
	}
	if forwarded {
		s.Forwarded++
	} else {
		s.Denied++
	}
	t := e.Time
	s.LastUsed = &t
}

// since returns events with Seq > after, oldest first, at most limit.
func (l *eventLog) since(after uint64, limit int) []Event {
	l.mu.Lock()
	defer l.mu.Unlock()
	var all []Event
	if l.full {
		all = append(all, l.buf[l.next:]...)
	}
	all = append(all, l.buf[:l.next]...)
	out := []Event{}
	for _, e := range all {
		if e.Seq > after {
			out = append(out, e)
		}
	}
	if len(out) > limit {
		out = out[len(out)-limit:]
	}
	return out
}

func (l *eventLog) snapshot() (map[string]KeyStats, int64, int64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	m := make(map[string]KeyStats, len(l.stats))
	for k, v := range l.stats {
		m[k] = *v
	}
	return m, l.total.forwarded, l.total.denied
}
