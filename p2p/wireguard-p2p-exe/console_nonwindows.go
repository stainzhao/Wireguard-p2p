//go:build !windows

package main

func acquireSingleInstance() bool {
	return true
}

func installConsoleCloseHandler() (<-chan struct{}, chan struct{}) {
	return make(chan struct{}), make(chan struct{})
}
