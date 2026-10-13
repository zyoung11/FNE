package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/schollz/progressbar/v3"
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

// validateDirectory checks if a path is a valid directory
func validateDirectory(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

// cleanupBadFiles removes temporary files created during conversion
func cleanupBadFiles(dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if strings.HasSuffix(strings.ToLower(e.Name()), ".mp3-id3v2") {
			os.Remove(filepath.Join(dir, e.Name()))
		}
	}
}

// buildExistingFileSet builds a set of already converted file names
func buildExistingFileSet(dir string) map[string]struct{} {
	set := make(map[string]struct{})
	entries, err := os.ReadDir(dir)
	if err != nil {
		return set
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(e.Name()))
		if ext == ".mp3" || ext == ".flac" || ext == ".ogg" {
			name := strings.TrimSuffix(e.Name(), ext)
			set[name] = struct{}{}
		}
	}
	return set
}

// scanFilesRecursively scans a directory for supported audio files
func scanFilesRecursively(dir string, recursive bool) ([]string, []string, error) {
	var ncmFiles []string
	var qmc2Files []string

	if recursive {
		err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() {
				return nil
			}
			ext := strings.ToLower(filepath.Ext(info.Name()))
			if ext == ".ncm" {
				ncmFiles = append(ncmFiles, path)
			} else if isQMC2Format(ext) {
				qmc2Files = append(qmc2Files, path)
			}
			return nil
		})
		if err != nil {
			return nil, nil, err
		}
	} else {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return nil, nil, err
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			ext := strings.ToLower(filepath.Ext(e.Name()))
			if ext == ".ncm" {
				ncmFiles = append(ncmFiles, filepath.Join(dir, e.Name()))
			} else if isQMC2Format(ext) {
				qmc2Files = append(qmc2Files, filepath.Join(dir, e.Name()))
			}
		}
	}

	return ncmFiles, qmc2Files, nil
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

// main shows the mode menu and dispatches to the local or download workflow
func main() {
	globalConfig = loadConfigOrDefault()
	globalKeyReader = newKeyReader()
	for {
		state, _ := enterRawMode()
		choice := showMainMenu(globalKeyReader)
		leaveRawMode(state)
		clearScreen()
		switch choice {
		case 1:
			runLocalConvert()
		case 2:
			state, _ := enterRawMode()
			runDownloadMode()
			leaveRawMode(state)
			clearScreen()
		case 3:
			return
		}
	}
}

// runLocalConvert converts local NCM and QMC2 files picked on the terminal
func runLocalConvert() {
	config := globalConfig
	initAPIConfig(config.APIConcurrent, config.APIDelayMin, config.APIDelayMax)

	var inputFolder, outputFolder string
	if config.InputFolder != "" && validateDirectory(config.InputFolder) {
		inputFolder = config.InputFolder
	}
	if config.OutputFolder != "" {
		outputFolder = config.OutputFolder
	}

	if inputFolder == "" {
		selected, err := selectFolder("选择VipSongsDownload路径，默认路径 C:/CloudMusic/VipSongsDownload")
		if err != nil || selected == "" {
			logWarn("输入文件夹选择已取消")
			readLine(globalKeyReader, "按回车继续")
			return
		}
		inputFolder = selected
	}

	if outputFolder == "" {
		selected, err := selectFolder("选择保存文件夹路径")
		if err != nil || selected == "" {
			logWarn("输出文件夹选择已取消")
			readLine(globalKeyReader, "按回车继续")
			return
		}
		outputFolder = selected
	}

	if _, err := os.Stat(inputFolder); os.IsNotExist(err) {
		logError(fmt.Sprintf("输入文件夹不存在 %s", inputFolder))
		readLine(globalKeyReader, "按回车继续")
		return
	}
	_ = os.MkdirAll(outputFolder, 0755)

	ncmListOriginal, qmc2ListOriginal, err := scanFilesRecursively(inputFolder, config.Recursive)
	if err != nil {
		logError(fmt.Sprintf("扫描输入文件夹失败 %v", err))
		readLine(globalKeyReader, "按回车继续")
		return
	}

	existing := buildExistingFileSet(outputFolder)

	var ncmList, qmc2List []string
	for _, path := range ncmListOriginal {
		baseName := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
		if _, found := existing[baseName]; !found {
			ncmList = append(ncmList, path)
		}
	}
	for _, path := range qmc2ListOriginal {
		baseName := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
		if _, found := existing[baseName]; !found {
			qmc2List = append(qmc2List, path)
		}
	}

	total := len(ncmList) + len(qmc2List)
	skipped := (len(ncmListOriginal) - len(ncmList)) + (len(qmc2ListOriginal) - len(qmc2List))
	if skipped > 0 {
		logInfo(fmt.Sprintf("已跳过 %d 个已转换的文件", skipped))
	}

	if total == 0 {
		logWarn("没有需要转换的文件")
		readLine(globalKeyReader, "按回车继续")
		return
	}

	bar := progressbar.NewOptions(total,
		progressbar.OptionEnableColorCodes(true),
		progressbar.OptionShowBytes(false),
		progressbar.OptionSetWidth(50),
		progressbar.OptionSetDescription("Converting..."),
		progressbar.OptionSetPredictTime(true),
		progressbar.OptionFullWidth(),
		progressbar.OptionSetTheme(progressbar.Theme{
			Saucer:        "[green]█[reset]",
			SaucerHead:    "[green]>[reset]",
			SaucerPadding: " ",
			BarStart:      "[",
			BarEnd:        "]",
		}),
		progressbar.OptionOnCompletion(func() { fmt.Println() }),
	)

	var (
		success, flacCount, mp3Count int
		failedFiles                  []string
		mu                           sync.Mutex
	)

	start := time.Now()
	const workerCount = 8

	jobs := make(chan string, total)
	var wg sync.WaitGroup

	for range workerCount {
		wg.Go(func() {
			for path := range jobs {
				var format string
				var err error
				ext := strings.ToLower(filepath.Ext(path))
				if isQMC2Format(ext) {
					format, err = convertQMC2File(path, outputFolder)
				} else {
					format, err = convertNcmFile(path, outputFolder)
				}
				mu.Lock()
				if err != nil {
					failedFiles = append(failedFiles, fmt.Sprintf("%s: %v", filepath.Base(path), err))
				} else {
					success++
					switch format {
					case "flac":
						flacCount++
					case "mp3":
						mp3Count++
					}
				}
				mu.Unlock()
				bar.Add(1)
			}
		})
	}

	for _, path := range ncmList {
		jobs <- path
	}
	for _, path := range qmc2List {
		jobs <- path
	}
	close(jobs)
	wg.Wait()

	cleanupBadFiles(outputFolder)

	elapsed := time.Since(start)
	speed := float64(total) / elapsed.Seconds()

	fmt.Println()
	fmt.Println("============================================================")
	fmt.Printf("  Input:     %s\n", inputFolder)
	fmt.Printf("  Output:    %s\n", outputFolder)
	fmt.Printf("  Total:     %d\n", total)
	fmt.Printf("  Success:   %d (FLAC: %d, MP3: %d)\n", success, flacCount, mp3Count)
	fmt.Printf("  Failed:    %d\n", len(failedFiles))
	fmt.Printf("  Skipped:   %d\n", skipped)
	fmt.Printf("  Time:      %.1fs (%.1f files/s)\n", elapsed.Seconds(), speed)
	if len(failedFiles) > 0 {
		fmt.Println("------------------------------------------------------------")
		fmt.Println("  Failed files:")
		for _, f := range failedFiles {
			fmt.Printf("    - %s\n", f)
		}
	}
	fmt.Println("============================================================")
	fmt.Println()
	readLine(globalKeyReader, "按回车继续")
}

// runDownloadMode starts the browser download workflow and mirrors its state in the TUI
func runDownloadMode() {
	client := newNeteaseClient()
	status := &downloadStatus{}
	dl := newDownloader(client, status, globalConfig.NameFormat)
	srv := newWebServer(client, dl, status, webUIHTML)
	port, err := srv.Start()
	if err != nil {
		logError(fmt.Sprintf("启动 Web 服务失败 %v", err))
		readLine(globalKeyReader, "按回车继续")
		return
	}
	openBrowser(fmt.Sprintf("http://127.0.0.1:%d", port))
	runDownloadUI(globalKeyReader, status, port)
	srv.Stop()
}
