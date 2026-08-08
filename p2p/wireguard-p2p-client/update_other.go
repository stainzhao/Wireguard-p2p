//go:build !windows && !linux

package main

import "errors"

func applyPlatformUpdate(_ []byte, _ string) error {
	return errors.New("automatic update is unsupported on this platform")
}
