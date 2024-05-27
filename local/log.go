package local

import "github.com/jedisct1/dlog"

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

type dlogT struct{}

func (d dlogT) Debugf(msg string, args ...interface{}) {
	dlog.Debugf(msg, args...)
}

func (d dlogT) Infof(msg string, args ...interface{}) {
	dlog.Infof(msg, args...)
}

func (d dlogT) Warnf(msg string, args ...interface{}) {
	dlog.Warnf(msg, args...)
}

func (d dlogT) Errorf(msg string, args ...interface{}) {
	dlog.Errorf(msg, args...)
}

func (d dlogT) Fatalf(msg string, args ...interface{}) {
	dlog.Fatalf(msg, args...)
}

var log Logger = dlogT{}

// SetLogger allows users to inject their own logger instead of the default one.
func SetLogger(l Logger) {
	log = l
}
