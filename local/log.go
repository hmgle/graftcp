package local

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

// Logger represents a general-purpose logger.
type Logger interface {
	// Fatalf is critical fatal logging, should possibly followed by system shutdown
	Fatalf(msg string, args ...interface{})

	// Errorf is for logging errors
	Errorf(msg string, args ...interface{})

	// Warnf is for logging messages about possible issues
	Warnf(msg string, args ...interface{})

	// Infof for logging general logging messages
	Infof(msg string, args ...interface{})

	// Debugf is for logging verbose messages
	Debugf(msg string, args ...interface{})
}

type discardLogger struct{}

func (d discardLogger) Debugf(msg string, args ...interface{}) {}
func (d discardLogger) Infof(msg string, args ...interface{})  {}
func (d discardLogger) Warnf(msg string, args ...interface{})  {}
func (d discardLogger) Errorf(msg string, args ...interface{}) {}

func (d discardLogger) Fatalf(msg string, args ...interface{}) {
	os.Exit(255)
}

type writerLogger struct {
	mu sync.Mutex
	w  io.Writer
}

// NewLogger returns a logger that writes formatted log lines to w.
func NewLogger(w io.Writer) Logger {
	if w == nil {
		return discardLogger{}
	}
	return &writerLogger{w: w}
}

// NewStderrLogger returns a logger that writes formatted log lines to stderr.
func NewStderrLogger() Logger {
	return NewLogger(os.Stderr)
}

func (l *writerLogger) Debugf(msg string, args ...interface{}) {
	l.logf("DEBUG", msg, args...)
}

func (l *writerLogger) Infof(msg string, args ...interface{}) {
	l.logf("INFO", msg, args...)
}

func (l *writerLogger) Warnf(msg string, args ...interface{}) {
	l.logf("WARNING", msg, args...)
}

func (l *writerLogger) Errorf(msg string, args ...interface{}) {
	l.logf("ERROR", msg, args...)
}

func (l *writerLogger) Fatalf(msg string, args ...interface{}) {
	l.logf("FATAL", msg, args...)
	os.Exit(255)
}

func (l *writerLogger) logf(level, msg string, args ...interface{}) {
	message := fmt.Sprintf(msg, args...)
	message = strings.TrimSpace(strings.TrimSuffix(message, "\n"))
	if message == "" {
		return
	}

	line := fmt.Sprintf("[%s] [%s] %s\n", time.Now().Local().Format("2006-01-02 15:04:05"), level, message)
	l.mu.Lock()
	defer l.mu.Unlock()
	_, _ = io.WriteString(l.w, line)
}

var log Logger = discardLogger{}

// SetLogger allows users to inject their own logger instead of the default one.
func SetLogger(l Logger) {
	if l == nil {
		log = discardLogger{}
		return
	}
	log = l
}
