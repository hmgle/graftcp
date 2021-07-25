package main

import "github.com/hmgle/graftcp/local"

type noopLogger struct{}

func (n noopLogger) Debugf(msg string, args ...interface{}) {}
func (n noopLogger) Infof(msg string, args ...interface{})  {}
func (n noopLogger) Warnf(msg string, args ...interface{})  {}
func (n noopLogger) Errorf(msg string, args ...interface{}) {}
func (n noopLogger) Fatalf(msg string, args ...interface{}) {}

var _ local.Logger = noopLogger{}
