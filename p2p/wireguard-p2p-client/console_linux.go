//go:build linux

package main

import (
	"os"
	"os/signal"
	"sync"
	"syscall"
)

var instanceLockFile *os.File

func acquireSingleInstance() bool {
	const runtimeDir = "/run/wireguard-p2p-client"
	if err := os.MkdirAll(runtimeDir, 0755); err != nil {
		return false
	}
	file, err := os.OpenFile(runtimeDir+"/client.lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return false
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = file.Close()
		return false
	}
	instanceLockFile = file
	return true
}

func installConsoleCloseHandler() (<-chan struct{}, chan struct{}) {
	shutdown := make(chan struct{})
	cleanupDone := make(chan struct{})
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
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

func requestRunningInstanceStop() error { return nil }
