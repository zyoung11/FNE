//go:build windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/schollz/progressbar/v3"
)

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

// menuItem is one selectable entry of the main menu
type menuItem struct {
	label string
	value int
}

// showMainMenu renders the centered mode menu and returns the chosen mode value
func showMainMenu(kr *keyReader) int {
	items := []menuItem{
		{label: "本地转换", value: 1},
		{label: "在线下载", value: 2},
	}
	cursor := 0
	for {
		w, h := termSize()
		var b strings.Builder
		b.WriteString("\x1b[2J\x1b[3J\x1b[H")
		startRow := max((h-len(items)-3)/2+1, 1)
		for row := 1; row < startRow; row++ {
			b.WriteString("\r\n")
		}
		for i, it := range items {
			if i == cursor {
				b.WriteString(centerLine(colorAccent+" > "+it.label+" <"+colorReset, w))
			} else {
				b.WriteString(centerLine(colorText3+"   "+it.label+"   "+colorReset, w))
			}
			b.WriteString("\r\n")
		}
		fmt.Fprintf(&b, "\x1b[%d;1H", h)
		b.WriteString(centerLine(colorHint+"方向键 选择    Enter 确认    q 退出"+colorReset, w))
		fmt.Print(b.String())
		key := <-kr.keys
		switch key {
		case KeyArrowUp, KeyArrowLeft:
			cursor = (cursor - 1 + len(items)) % len(items)
		case KeyArrowDown, KeyArrowRight:
			cursor = (cursor + 1) % len(items)
		case KeyEnter:
			return items[cursor].value
		case '1':
			return 1
		case '2':
			return 2
		case 'q', 'Q':
			return 3
		}
	}
}

// runApp shows the mode menu and dispatches to the chosen workflow
func runApp() {
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
