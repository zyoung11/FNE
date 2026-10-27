//go:build windows

package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	winfilepicker "FNE/winfilepicker"
)

// configDir returns the directory holding config and cookie files, the exe directory for the portable build
func configDir() (string, error) {
	exePath, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.Dir(exePath), nil
}

// selectFolder opens a native folder dialog and returns the chosen path
func selectFolder(prompt string) (string, error) {
	return winfilepicker.SelectFolder(prompt)
}

// pickDownloadFolder opens a native folder dialog for the web download mode
func pickDownloadFolder() (string, error) {
	folder, err := winfilepicker.SelectFolder("选择保存文件夹路径")
	if errors.Is(err, winfilepicker.ErrCancelled) {
		return "", errPickCancelled
	}
	return folder, err
}

// loadLastFolder is unused on Windows because the save folder is not recorded
func loadLastFolder() string {
	return ""
}

// saveLastFolder is unused on Windows because the save folder is not recorded
func saveLastFolder(_ string) error {
	return nil
}

// runtimePlatform returns the platform identifier reported to the web UI
func runtimePlatform() string {
	return "windows"
}

// preserveCreationTime copies the creation time from src to dst
func preserveCreationTime(src, dst string) {
	info, err := os.Stat(src)
	if err != nil {
		return
	}
	winAttr, ok := info.Sys().(*syscall.Win32FileAttributeData)
	if !ok {
		return
	}
	creationTime := winAttr.CreationTime
	dstPtr, err := syscall.UTF16PtrFromString(dst)
	if err != nil {
		return
	}
	h, err := syscall.CreateFile(
		dstPtr,
		syscall.FILE_WRITE_ATTRIBUTES,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE,
		nil,
		syscall.OPEN_EXISTING,
		syscall.FILE_FLAG_BACKUP_SEMANTICS,
		0,
	)
	if err != nil {
		return
	}
	defer syscall.CloseHandle(h)
	syscall.SetFileTime(h, &creationTime, nil, nil)
}

// openBrowser launches the default browser at the given URL
func openBrowser(url string) error {
	return exec.Command("cmd", "/c", "start", "", url).Start()
}

// isQMC2Format reports whether the extension is a QMC2 encrypted format
func isQMC2Format(ext string) bool {
	switch ext {
	case ".mflac", ".mflac0", ".mflach", ".mgg", ".mgg0", ".mgg1", ".mggl":
		return true
	}
	return false
}

// setFileOrderTime assigns the creation time used to keep playlist order in Explorer
func setFileOrderTime(path string, t time.Time) {
	pathPtr, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return
	}
	h, err := syscall.CreateFile(
		pathPtr,
		syscall.FILE_WRITE_ATTRIBUTES,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE,
		nil,
		syscall.OPEN_EXISTING,
		syscall.FILE_FLAG_BACKUP_SEMANTICS,
		0,
	)
	if err != nil {
		return
	}
	defer syscall.CloseHandle(h)
	c := syscall.NsecToFiletime(t.UnixNano())
	syscall.SetFileTime(h, &c, nil, nil)
}

// downloadQuitHint returns the bottom hint text for leaving the download mode
func downloadQuitHint() string {
	return "按 q 返回"
}
