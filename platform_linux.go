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

// selectFolder prompts for a folder path on the terminal and returns it after validation
func selectFolder(prompt string) (string, error) {
	for {
		path := readLine(globalKeyReader, prompt)
		if path == "" {
			return "", fmt.Errorf("folder selection cancelled")
		}
		if validateDirectory(path) {
			return path, nil
		}
		logWarn("路径不存在或不是文件夹，请重新输入")
	}
}

// pickDownloadFolder is unused on Linux because the web UI provides a text input for the path
func pickDownloadFolder() (string, error) {
	return "", fmt.Errorf("folder selection happens in the browser on this platform")
}

// runtimePlatform returns the platform identifier reported to the web UI
func runtimePlatform() string {
	return "linux"
}

// preserveCreationTime is a no-op because Linux creation timestamps cannot be set
func preserveCreationTime(src, dst string) {
}

// openBrowser launches the default browser at the given URL
func openBrowser(url string) error {
	return exec.Command("xdg-open", url).Start()
}

// isQMC2Format always returns false because QMC2 decryption requires the Windows QQ Music client
func isQMC2Format(_ string) bool {
	return false
}
