//go:build linux

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
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

// stateFilePath returns the path of the runtime state file in the config directory
func stateFilePath() (string, error) {
	dir, err := configDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "state.json"), nil
}

// loadLastFolder returns the save folder recorded by the previous run, or an empty string
func loadLastFolder() string {
	path, err := stateFilePath()
	if err != nil {
		return ""
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	var state struct {
		LastFolder string `json:"lastFolder"`
	}
	if err := json.Unmarshal(data, &state); err != nil {
		return ""
	}
	return state.LastFolder
}

// saveLastFolder records the save folder used by the latest download
func saveLastFolder(folder string) error {
	path, err := stateFilePath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(map[string]string{"lastFolder": folder}, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
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
	runDownloadMode()
	clearScreen()
}

// setFileOrderTime assigns the modification time used to keep playlist order in file managers
func setFileOrderTime(path string, t time.Time) {
	_ = os.Chtimes(path, t, t)
}

// downloadQuitHint returns the bottom hint text for leaving the download mode
func downloadQuitHint() string {
	return "按 q 退出"
}
