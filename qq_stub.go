//go:build !windows

package main

import "errors"

// errQMC2Unsupported is returned when QMC2 conversion is requested on a non-Windows platform
var errQMC2Unsupported = errors.New("QMC2 decryption is only supported on Windows")

// initAPIConfig is a no-op stub because QMC2 conversion is unavailable on this platform
func initAPIConfig(concurrent, delayMin, delayMax int) {
}

// convertQMC2File always fails because QMC2 decryption requires the Windows QQ Music client
func convertQMC2File(_, _ string) (string, error) {
	return "", errQMC2Unsupported
}
