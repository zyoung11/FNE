//go:build linux

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// configDir returns the directory holding config and cookie files under the user config home
func configDir() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "FNE"), nil
}

// pickDownloadFolder is unused on Linux because the web UI provides a text input for the path
func pickDownloadFolder() (string, error) {
	return "", fmt.Errorf("folder selection happens in the browser on this platform")
}

// preserveCreationTime is a no-op because Linux creation timestamps cannot be set
func preserveCreationTime(src, dst string) {
}

// openBrowser launches the default browser at the given URL
func openBrowser(url string) error {
	return exec.Command("xdg-open", url).Start()
}

// runtimePlatform returns the platform identifier reported to the web UI
func runtimePlatform() string {
	return "linux"
}

// runApp starts the online download workflow directly because local conversion has no use case on Linux
func runApp() {
	state, _ := enterRawMode()
	runDownloadMode()
	leaveRawMode(state)
	clearScreen()
}

// downloadQuitHint returns the bottom hint text for leaving the download mode
func downloadQuitHint() string {
	return "按 q 退出"
}
