package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// appConfig holds the application configuration
type appConfig struct {
	InputFolder   string `json:"inputFolder"`
	OutputFolder  string `json:"outputFolder"`
	Recursive     bool   `json:"recursive"`
	APIConcurrent int    `json:"apiConcurrent"`
	APIDelayMin   int    `json:"apiDelayMin"`
	APIDelayMax   int    `json:"apiDelayMax"`
	NameFormat    string `json:"nameFormat"`
	DefaultMode   string `json:"defaultMode"`
}

// loadConfig loads configuration from config.json in the platform config directory
func loadConfig() (*appConfig, error) {
	dir, err := configDir()
	if err != nil {
		return nil, fmt.Errorf("get config dir: %w", err)
	}
	configPath := filepath.Join(dir, "config.json")

	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("read config file: %w", err)
	}

	var config appConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("parse config file: %w", err)
	}

	return &config, nil
}

// globalKeyReader is the shared terminal input decoder
var globalKeyReader *keyReader

// globalConfig holds the active application configuration
var globalConfig *appConfig

// defaultDownloadFolder returns the configured default save folder for the download mode
func defaultDownloadFolder() string {
	if globalConfig == nil {
		return ""
	}
	return globalConfig.OutputFolder
}

// loadConfigOrDefault loads config.json or falls back to defaults when it is missing
func loadConfigOrDefault() *appConfig {
	config, err := loadConfig()
	if err != nil {
		config = &appConfig{}
	}
	if config.APIConcurrent <= 0 {
		config.APIConcurrent = 3
	}
	if config.APIDelayMin < 0 {
		config.APIDelayMin = 200
	}
	if config.APIDelayMax < config.APIDelayMin {
		config.APIDelayMax = config.APIDelayMin + 600
	}
	if config.NameFormat == "" {
		config.NameFormat = "artist - title"
	}
	return config
}

// main starts the platform specific application entry
func main() {
	globalConfig = loadConfigOrDefault()
	state, err := enterRawMode()
	if err != nil {
		logError(fmt.Sprintf("切换终端原始模式失败 %v", err))
		os.Exit(1)
	}
	globalKeyReader = newKeyReader()
	runApp()
	leaveRawMode(state)
}

// runDownloadMode starts the browser download workflow and returns true when the user pressed Ctrl+C
func runDownloadMode() bool {
	client := newNeteaseClient()
	status := &downloadStatus{}
	dl := newDownloader(client, status, globalConfig.NameFormat)
	srv := newWebServer(client, dl, status, webUIIndex())
	port, err := srv.Start()
	if err != nil {
		logError(fmt.Sprintf("启动 Web 服务失败 %v", err))
		readLine(globalKeyReader, "按回车继续")
		return false
	}
	openBrowser(fmt.Sprintf("http://127.0.0.1:%d", port))
	quit := runDownloadUI(globalKeyReader, status, port)
	srv.Stop()
	return quit
}
