package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/schollz/progressbar/v3"
	winfilepicker "github.com/zyoung11/GO-WinFilePicker"
)

// appConfig holds the application configuration
type appConfig struct {
	InputFolder   string `json:"inputFolder"`
	OutputFolder  string `json:"outputFolder"`
	Recursive     bool   `json:"recursive"`
	APIConcurrent int    `json:"apiConcurrent"`
	APIDelayMin   int    `json:"apiDelayMin"`
	APIDelayMax   int    `json:"apiDelayMax"`
}

// loadConfig loads configuration from config.json in the same directory as the executable
func loadConfig() (*appConfig, error) {
	exePath, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("get executable path: %w", err)
	}
	exeDir := filepath.Dir(exePath)
	configPath := filepath.Join(exeDir, "config.json")

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

// isQMC2Format checks if the file extension is a QMC2 encrypted format
func isQMC2Format(ext string) bool {
	switch ext {
	case ".mflac", ".mflac0", ".mflach", ".mgg", ".mgg0", ".mgg1", ".mggl":
		return true
	}
	return false
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

func main() {
	if rand.Intn(2) == 0 {
		printASCII_1()
	} else {
		printASCII_2()
	}

	var inputFolder, outputFolder string
	var recursive bool

	config, err := loadConfig()
	if err != nil {
		initAPIConfig(3, 200, 800)
	} else {
		if config.InputFolder != "" {
			if validateDirectory(config.InputFolder) {
				inputFolder = config.InputFolder
			}
		}
		if config.OutputFolder != "" {
			outputFolder = config.OutputFolder
		}
		recursive = config.Recursive
		initAPIConfig(config.APIConcurrent, config.APIDelayMin, config.APIDelayMax)
	}

	if inputFolder == "" {
		selected, err := winfilepicker.SelectFolder("选择VipSongsDownload路径，默认路径：C:/CloudMusic/VipSongsDownload")
		if err != nil || selected == "" {
			fmt.Println("Input folder selection cancelled:", err)
			os.Exit(0)
		}
		inputFolder = selected
	}

	if outputFolder == "" {
		selected, err := winfilepicker.SelectFolder("选择保存文件夹路径")
		if err != nil || selected == "" {
			fmt.Println("Output folder selection cancelled:", err)
			os.Exit(0)
		}
		outputFolder = selected
	}

	if _, err := os.Stat(inputFolder); os.IsNotExist(err) {
		fmt.Printf("Input folder does not exist: %s\n", inputFolder)
		os.Exit(1)
	}
	_ = os.MkdirAll(outputFolder, 0755)

	// Scan for files
	ncmListOriginal, qmc2ListOriginal, err := scanFilesRecursively(inputFolder, recursive)
	if err != nil {
		fmt.Printf("Scan input folder error: %v\n", err)
		os.Exit(1)
	}

	existing := buildExistingFileSet(outputFolder)

	// Filter out already converted files
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
		fmt.Printf("Skipped %d already converted files.\n", skipped)
	}

	if total == 0 {
		fmt.Println("No files to convert.")
		os.Exit(0)
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
	fmt.Print("Press Enter to exit...")
	bufio.NewReader(os.Stdin).ReadBytes('\n')
}

func printASCII_1() {
	fmt.Print(`



				[0;37;40m▄[0;97;1;40m▀███████████▀[0;90;1;40m▄█[0;37;40m [0;97;1;40m▀██[0;97;1;47m▀[0;97;1;40m███▀[0;37;40m    [0;97;1;40m▀██[0;97;1;47m▀[0;97;1;40m██▀[0;37;40m [0;97;1;40m▀█████████████▀[0;90;1;40m▄[0m
				[0;37;40m█▄[0;97;1;40m▀███▀[0;90;1;40m▄[0;37;40m     [0;90;1;40m▀██[0;37;40m █▄[0;97;1;40m▀██▀[0;37;40m [0;90;1;40m▄▀[0;37;40m   █ [0;97;1;40m█[0;97;1;47m▄[0;97;1;40m█[0;37;40m [0;90;1;40m█[0;37;40m █▄▄[0;97;1;40m▀▀▀▀▀▀▀▀▀▀[0;90;1;40m▄██[0m
				[0;37;40m██▄[0;97;1;40m▀▀[0;90;1;40m▄█[0;37;40m        [0;90;1;40m▀[0;37;40m ██▄[0;97;1;40m▀[0;37;40m [0;90;1;40m▄█▄▀[0;37;40m   ██▄[0;97;1;40m▀[0;90;1;40m▄██[0;37;40m ██▀▀        [0;90;1;40m▀▀██[0m
				[0;37;40m███ [0;90;1;40m██▀[0;37;40m          ███ [0;90;1;40m█████▄[0;37;40m  ███ [0;90;1;40m███[0;37;40m ▄ [0;97;1;40m▄▄▄▄▄▄▄▄▄▄▄▄[0;37;40m [0;90;1;40m▄[0m
				[0;37;40m███ [0;90;1;40m▀[0;97;1;40m▄▄▄▄▄▄▄▄[0;37;40m [0;90;1;40m▄[0;37;40m  █[0;97;1;47m▄[0;37;40m█ [0;90;1;40m███[0;37;40m ▀▄[0;90;1;40m▀▄[0;37;40m▀██ [0;90;1;40m███[0;37;40m ██▄[0;97;1;40m▀█████████[0;37;40m [0;90;1;40m██[0m
				[0;37;40m███ [0;97;1;40m▀▀▀▀▀▀▀▀[0;90;1;40m▄██[0;37;40m  [0;97;1;47m▄[0;90;1;40m▀[0;97;1;40m█[0;37;40m [0;90;1;40m██[0;37;40m [0;90;1;40m▀[0;37;40m ▄█▄[0;90;1;40m▀[0;37;40m▄█ [0;90;1;40m███[0;37;40m █▀           [0;90;1;40m▀██[0m
				[0;37;40m███ [0;90;1;40m█▄[0;37;40m▀█▀    [0;90;1;40m▀█[0;37;40m  [0;90;1;40m▄[0;37;40m▄[0;97;1;40m▄[0;37;40m [0;90;1;40m██▄[0;37;40m   ▀████ [0;90;1;40m███[0;37;40m                [0;90;1;40m▀[0m
				[0;37;40m███ [0;90;1;40m███[0;37;40m          ▀[0;90;1;40m▄[0;37;40m█ [0;90;1;40m██[0;37;40m     ▀███ [0;90;1;40m███[0;37;40m █▄[0;97;1;40m▀██████████▀[0;90;1;40m██[0m
				[0;37;40m██▀ [0;90;1;40m███[0;37;40m          [0;90;1;40m▄[0;97;1;40m█[0;37;40m█ [0;90;1;40m██[0;37;40m [0;90;1;40m▀[0;37;40m    ▄██ [0;90;1;40m███[0;37;40m ███ [0;97;1;40m▀▀▀▀▀▀▀▀[0;37;40m [0;90;1;40m███[0m
				[0;37;40m▀    [0;90;1;40m▀█[0;37;40m          █▀   [0;90;1;40m▀█▄[0;37;40m    ▄▀   [0;90;1;40m▀█[0;37;40m █▀            [0;90;1;40m▀█[0m





`)
}

func printASCII_2() {
	fmt.Print(`


					[0;37;40m  [0;31;40m▄▄[0;91;1;41m·▀▀[0;91;1;40m▄▄▄[0;37;40m  [0;31;40m▄█[0;91;1;41m▀[0;31;40m▄[0;37;40m [0;31;40m▄[0;91;1;41m▀▀█[0;91;1;40m▄[0;37;40m   [0;31;40m▄▄[0;91;1;41m·▀▀[0;91;1;40m▄▄▄[0;37;40m [0m
					[0;37;40m [0;91;1;41m■[0;37;41m▄▄[0;31;40m█[0;91;1;41m·[0;31;40m█[0;37;41m▄[0;37;40m█[0;31;40m█[0;91;1;41m▀[0;31;40m▐█[0;91;1;41m·[0;31;47m▌[0;97;1;47m▄[0;37;40m [0;90;1;40m█[0;31;47m▀[0;91;1;41m■[0;31;47m▌[0;97;1;40m█[0;31;40m▌[0;37;40m [0;91;1;41m■[0;37;41m▄▄[0;31;40m█[0;91;1;41m·[0;31;40m█[0;37;41m▄[0;37;40m█[0;31;40m█[0;91;1;41m▀[0m
					[0;31;40m▐[0;90;1;40m█[0;37;40m██[0;37;41m▐[0;97;1;47m▀[0;37;40m▄▄[0;97;1;40m▄[0;37;40m [0;91;1;40m▌[0;90;1;41m▌[0;37;41m▄▌▐[0;37;40m█[0;97;1;47m▀[0;97;1;41m▄[0;37;40m█[0;37;41m▄[0;91;1;47m▌[0;97;1;40m█[0;37;40m [0;31;40m▐[0;90;1;40m█[0;37;40m██[0;37;41m▐[0;97;1;47m▀[0;37;40m▄▄[0;97;1;40m▄[0;37;40m [0;91;1;40m▌[0m
					[0;37;40m [0;90;1;40m█[0;37;40m███[0;97;1;47m▄[0;37;40m▀▀[0;97;1;40m▀[0;37;40m  [0;90;1;40m█[0;37;40m█[0;37;41m▐[0;37;40m█[0;97;1;40m█[0;90;1;47m▄[0;37;40m██[0;37;41m█▐[0;97;1;40m█[0;37;40m  [0;90;1;40m█[0;37;40m███[0;97;1;47m▄[0;37;40m▀▀[0;97;1;40m▀[0;37;40m  [0m
					[0;37;40m [0;90;1;40m█[0;37;40m███[0;97;1;40m█[0;37;40m     [0;90;1;40m█[0;37;40m███[0;97;1;40m█[0;90;1;40m▀█[0;37;40m███[0;97;1;40m█[0;37;40m  [0;90;1;40m█[0;37;40m███[0;97;1;40m█[0;31;40m▄[0;91;1;41m▀[0;91;1;40m▄[0;37;40m  [0m
					[0;37;40m [0;90;1;40m█[0;90;1;47m   [0;97;1;40m█[0;37;40m     [0;90;1;40m█[0;37;40m███[0;97;1;40m█[0;37;40m [0;90;1;40m█[0;37;40m███[0;97;1;40m█[0;37;40m  [0;90;1;40m█[0;90;1;47m    [0;31;47m▐▀ [0;97;1;40m█[0;37;40m [0m
					[0;37;40m [0;90;1;40m▀[0;37;40m▀▀▀[0;97;1;40m▀[0;37;40m     [0;90;1;40m▀[0;37;40m▀▀▀[0;97;1;40m▀[0;37;40m [0;90;1;40m▀[0;37;40m▀▀▀[0;97;1;40m▀[0;37;40m  [0;90;1;40m▀[0;37;40m▀▀▀▀▀▀▀[0;97;1;40m▀[0;37;40m [0m



`)
}
