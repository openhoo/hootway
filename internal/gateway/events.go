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

// keyStats is the allocation-free internal form of KeyStats.
type keyStats struct {
	forwarded, denied int64
	lastUsed          time.Time
}

// eventLog is a fixed-size ring of recent events plus per-key counters. The
// critical section of add is a struct copy and a few counter updates, and it
// never allocates once a key has been seen.
type eventLog struct {
	mu    sync.Mutex
	buf   []Event
	seq   uint64 // sequence number of the newest event; buf[(seq-1)%len] holds it
	stats map[string]*keyStats
	total struct{ forwarded, denied int64 }
}

func newEventLog(n int) *eventLog {
	return &eventLog{buf: make([]Event, n), stats: map[string]*keyStats{}}
}

func (l *eventLog) add(e Event) {
	forwarded := e.Outcome == "forwarded"
	l.mu.Lock()
	l.seq++
	e.Seq = l.seq
	l.buf[(l.seq-1)%uint64(len(l.buf))] = e
	if forwarded {
		l.total.forwarded++
	} else {
		l.total.denied++
	}
	if e.Key != "" {
		s := l.stats[e.Key]
		if s == nil {
			s = &keyStats{}
			l.stats[e.Key] = s
		}
		if forwarded {
			s.forwarded++
		} else {
			s.denied++
		}
		s.lastUsed = e.Time
	}
	l.mu.Unlock()
}

// since returns events with Seq > after, oldest first, at most limit.
func (l *eventLog) since(after uint64, limit int) []Event {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := uint64(len(l.buf))
	oldest := uint64(1)
	if l.seq > n {
		oldest = l.seq - n + 1
	}
	from := max(after+1, oldest)
	if limit >= 0 && l.seq >= from && l.seq-from+1 > uint64(limit) {
		from = l.seq - uint64(limit) + 1
	}
	if limit < 0 || from > l.seq {
		return []Event{}
	}
	out := make([]Event, 0, l.seq-from+1)
	for s := from; s <= l.seq; s++ {
		out = append(out, l.buf[(s-1)%n])
	}
	return out
}

func (l *eventLog) snapshot() (map[string]KeyStats, int64, int64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	m := make(map[string]KeyStats, len(l.stats))
	for k, v := range l.stats {
		ks := KeyStats{Forwarded: v.forwarded, Denied: v.denied}
		if !v.lastUsed.IsZero() {
			t := v.lastUsed
			ks.LastUsed = &t
		}
		m[k] = ks
	}
	return m, l.total.forwarded, l.total.denied
}
