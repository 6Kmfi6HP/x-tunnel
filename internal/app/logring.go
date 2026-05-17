package app

import (
	"bytes"
	"io"
	"log"
	"strings"
	"sync"
	"time"
)

type LogEntry struct {
	ID        uint64            `json:"id"`
	Time      time.Time         `json:"time"`
	Level     string            `json:"level"`
	Component string            `json:"component,omitempty"`
	Message   string            `json:"message"`
	Fields    map[string]string `json:"fields,omitempty"`
}

type LogRing struct {
	mu      sync.RWMutex
	entries []LogEntry
	next    int
	full    bool
	seq     uint64
}

func NewLogRing(limit int) *LogRing {
	if limit <= 0 {
		limit = 256
	}
	return &LogRing{entries: make([]LogEntry, limit)}
}

func (r *LogRing) Add(message string) {
	if r == nil {
		return
	}
	message = strings.TrimSpace(message)
	if message == "" {
		return
	}
	r.mu.Lock()
	r.seq++
	entry := LogEntry{
		ID:      r.seq,
		Time:    time.Now().UTC(),
		Level:   "info",
		Message: redactConfigValue(message),
	}
	if strings.HasPrefix(entry.Message, "[") {
		if end := strings.Index(entry.Message, "]"); end > 1 {
			entry.Component = entry.Message[1:end]
		}
	}
	r.entries[r.next] = entry
	r.next = (r.next + 1) % len(r.entries)
	if r.next == 0 {
		r.full = true
	}
	r.mu.Unlock()
}

func (r *LogRing) Entries(limit int) []LogEntry {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	count := r.next
	start := 0
	if r.full {
		count = len(r.entries)
		start = r.next
	}
	if limit <= 0 || limit > count {
		limit = count
	}
	out := make([]LogEntry, 0, limit)
	first := count - limit
	for i := first; i < count; i++ {
		idx := (start + i) % len(r.entries)
		out = append(out, r.entries[idx])
	}
	return out
}

func (r *LogRing) EntriesSince(after uint64, limit int) []LogEntry {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	count := r.next
	start := 0
	if r.full {
		count = len(r.entries)
		start = r.next
	}
	out := make([]LogEntry, 0, count)
	for i := 0; i < count; i++ {
		idx := (start + i) % len(r.entries)
		entry := r.entries[idx]
		if entry.ID > after {
			out = append(out, entry)
		}
	}
	if limit > 0 && len(out) > limit {
		out = out[len(out)-limit:]
	}
	return out
}

type logRingWriter struct {
	ring *LogRing
	next io.Writer
	sink Logger
	mu   sync.Mutex
	buf  bytes.Buffer
}

func (w *logRingWriter) Write(p []byte) (int, error) {
	var lines []string
	w.mu.Lock()
	_, _ = w.buf.Write(p)
	for {
		line, err := w.buf.ReadString('\n')
		if err != nil {
			_, _ = w.buf.WriteString(line)
			break
		}
		w.ring.Add(line)
		lines = append(lines, strings.TrimSpace(line))
	}
	w.mu.Unlock()
	if w.next != nil {
		_, _ = w.next.Write(p)
	}
	if w.sink != nil {
		for _, line := range lines {
			if line != "" {
				w.sink.Printf("%s", line)
			}
		}
	}
	return len(p), nil
}

func installLogRing(ring *LogRing, logger Logger) func() {
	old := log.Writer()
	if defaultLogger, ok := logger.(*log.Logger); ok && defaultLogger == log.Default() {
		logger = nil
	}
	writer := &logRingWriter{ring: ring, next: old, sink: logger}
	log.SetOutput(writer)
	return func() {
		log.SetOutput(old)
	}
}
