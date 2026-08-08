//go:build !windows && !linux

package main

import (
	"os"
	"os/signal"
	"sync"
)

func acquireSingleInstance() bool { return true }

func installConsoleCloseHandler() (<-chan struct{}, chan struct{}) {
	shutdown := make(chan struct{})
	cleanupDone := make(chan struct{})
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt)
	var once sync.Once
	go func() {
		select {
		case <-signals:
			once.Do(func() { close(shutdown) })
		case <-cleanupDone:
			signal.Stop(signals)
		}
	}()
	return shutdown, cleanupDone
}
