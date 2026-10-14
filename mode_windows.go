//go:build windows

package main

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
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
		case KeyCtrlC:
			return 3
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
		choice := showMainMenu(globalKeyReader)
		clearScreen()
		switch choice {
		case 1:
			sub := showConvertMenu(globalKeyReader)
			clearScreen()
			switch sub {
			case 1:
				runLocalConvert()
			case 2:
				runPlaylistConvert()
			case -1:
				return
			}
		case 2:
			if runDownloadMode() {
				return
			}
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

// ncmFileMetaInfo holds lightweight metadata parsed from an NCM header
type ncmFileMetaInfo struct {
	Title  string
	Artist string
}

// readNcmFileMeta extracts title and artist from the NCM metadata block without decrypting audio
func readNcmFileMeta(path string) (ncmFileMetaInfo, error) {
	file, err := os.Open(path)
	if err != nil {
		return ncmFileMetaInfo{}, err
	}
	defer file.Close()
	header := make([]byte, 8)
	if _, err := io.ReadFull(file, header); err != nil {
		return ncmFileMetaInfo{}, err
	}
	if string(header) != "CTENFDAM" {
		return ncmFileMetaInfo{}, fmt.Errorf("invalid ncm header")
	}
	if _, err := file.Seek(2, io.SeekCurrent); err != nil {
		return ncmFileMetaInfo{}, err
	}
	var keyLength uint32
	if err := binary.Read(file, binary.LittleEndian, &keyLength); err != nil {
		return ncmFileMetaInfo{}, err
	}
	if _, err := file.Seek(int64(keyLength), io.SeekCurrent); err != nil {
		return ncmFileMetaInfo{}, err
	}
	var metaLength uint32
	if err := binary.Read(file, binary.LittleEndian, &metaLength); err != nil {
		return ncmFileMetaInfo{}, err
	}
	metaDataEnc := make([]byte, metaLength)
	if _, err := io.ReadFull(file, metaDataEnc); err != nil {
		return ncmFileMetaInfo{}, err
	}
	for i := range metaDataEnc {
		metaDataEnc[i] ^= 0x63
	}
	metaDataB64, err := base64.StdEncoding.DecodeString(string(metaDataEnc[22:]))
	if err != nil {
		return ncmFileMetaInfo{}, err
	}
	block := newAESCipher(metaKey)
	dec := newECB(block)
	metaDataPadded := make([]byte, len(metaDataB64))
	dec.Decrypt(metaDataPadded, metaDataB64)
	metaDataJson := unpad(metaDataPadded)[6:]
	var meta ncmMetadata
	if err := json.Unmarshal(metaDataJson, &meta); err != nil {
		return ncmFileMetaInfo{}, err
	}
	return ncmFileMetaInfo{Title: meta.MusicName, Artist: parseArtist(meta.Artist)}, nil
}

// normalizeMatch normalizes a title or artist string for fuzzy comparison
func normalizeMatch(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.ReplaceAll(s, " ", "")
	s = strings.ReplaceAll(s, "　", "")
	return s
}

// artistNames splits an artist string into normalized single names
func artistNames(s string) []string {
	parts := strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == '/' || r == '、' || r == ';'
	})
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if n := normalizeMatch(p); n != "" {
			out = append(out, n)
		}
	}
	return out
}

// artistOverlap reports whether two artist strings share at least one name
func artistOverlap(a, b string) bool {
	left := artistNames(a)
	right := artistNames(b)
	for _, l := range left {
		if slices.Contains(right, l) {
			return true
		}
	}
	return false
}

// matchPlaylistFiles maps ordered playlist tracks to local encrypted files by metadata then filename
func matchPlaylistFiles(tracks []songItem, ncmMetas map[string]ncmFileMetaInfo, plainFiles []string) []string {
	used := make(map[string]bool)
	out := make([]string, len(tracks))
	for i, track := range tracks {
		for path, meta := range ncmMetas {
			if used[path] {
				continue
			}
			if normalizeMatch(meta.Title) == normalizeMatch(track.Name) && artistOverlap(meta.Artist, track.Artists) {
				out[i] = path
				used[path] = true
				break
			}
		}
	}
	pool := make([]string, 0, len(plainFiles))
	for _, path := range plainFiles {
		if !used[path] {
			pool = append(pool, path)
		}
	}
	for path := range ncmMetas {
		if !used[path] {
			pool = append(pool, path)
		}
	}
	for i, track := range tracks {
		if out[i] != "" {
			continue
		}
		nameNorm := normalizeMatch(track.Name)
		artistVariants := []string{normalizeMatch(track.Artists)}
		for _, n := range artistNames(track.Artists) {
			artistVariants = append(artistVariants, n)
		}
		for _, path := range pool {
			if used[path] {
				continue
			}
			base := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
			parts := strings.SplitN(base, " - ", 2)
			if len(parts) != 2 {
				continue
			}
			left, right := normalizeMatch(parts[0]), normalizeMatch(parts[1])
			for _, av := range artistVariants {
				if av == "" {
					continue
				}
				if (left == av && right == nameNorm) || (left == nameNorm && right == av) {
					out[i] = path
					used[path] = true
					break
				}
			}
			if out[i] != "" {
				break
			}
		}
	}
	return out
}

// playlistConvertRunner converts local encrypted files matching one playlist in track order
type playlistConvertRunner struct {
	mu         sync.Mutex
	job        *downloadJob
	client     *neteaseClient
	status     *downloadStatus
	ncmMetas   map[string]ncmFileMetaInfo
	plainFiles []string
	outputBase string
}

// newPlaylistConvertRunner prepares a conversion runner for the scanned local files
func newPlaylistConvertRunner(client *neteaseClient, status *downloadStatus, ncmMetas map[string]ncmFileMetaInfo, plainFiles []string, outputBase string) *playlistConvertRunner {
	return &playlistConvertRunner{
		client:     client,
		status:     status,
		ncmMetas:   ncmMetas,
		plainFiles: plainFiles,
		outputBase: outputBase,
	}
}

// Start begins a conversion job for the chosen playlist
func (r *playlistConvertRunner) Start(name string, ids []int64) error {
	r.mu.Lock()
	if r.job != nil && r.job.State == "running" {
		r.mu.Unlock()
		return fmt.Errorf("a conversion job is already running")
	}
	r.mu.Unlock()
	metaByID, err := r.client.SongsMeta(ids)
	if err != nil {
		return err
	}
	tracks := make([]songItem, 0, len(ids))
	for _, id := range ids {
		if item, ok := metaByID[id]; ok {
			tracks = append(tracks, item)
		} else {
			tracks = append(tracks, songItem{ID: id, Name: "未知歌曲"})
		}
	}
	paths := matchPlaylistFiles(tracks, r.ncmMetas, r.plainFiles)
	outDir := filepath.Join(r.outputBase, sanitizeFileName(name))
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return err
	}
	job := &downloadJob{Folder: outDir, State: "running"}
	job.Items = make([]downloadItem, len(tracks))
	for i, t := range tracks {
		job.Items[i] = downloadItem{Song: t, State: "pending"}
	}
	r.mu.Lock()
	r.job = job
	r.mu.Unlock()
	go r.run(job, paths)
	return nil
}

// Current returns a snapshot of the latest conversion job or nil
func (r *playlistConvertRunner) Current() *downloadJob {
	r.mu.Lock()
	job := r.job
	r.mu.Unlock()
	if job == nil {
		return nil
	}
	return job.snapshot()
}

// run converts all matched files in parallel and then stamps the playlist order
func (r *playlistConvertRunner) run(job *downloadJob, paths []string) {
	base := time.Now()
	var wg sync.WaitGroup
	sem := make(chan struct{}, 8)
	for i := range job.Items {
		if paths[i] == "" {
			job.setItem(i, "skipped", "本地无匹配文件")
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			ext := strings.ToLower(filepath.Ext(paths[i]))
			var format string
			var err error
			if isQMC2Format(ext) {
				format, err = convertQMC2File(paths[i], job.Folder)
			} else {
				format, err = convertNcmFile(paths[i], job.Folder)
			}
			if err != nil {
				job.setItem(i, "failed", err.Error())
				r.pushStatus(job, i, "失败", err.Error())
				return
			}
			outName := strings.TrimSuffix(filepath.Base(paths[i]), filepath.Ext(paths[i])) + "." + format
			setFileOrderTime(filepath.Join(job.Folder, outName), base.Add(time.Duration(i)*time.Second))
			job.setItem(i, "done", outName)
			r.pushStatus(job, i, "完成", outName)
		}(i)
	}
	wg.Wait()
	job.mu.Lock()
	job.State = "finished"
	job.mu.Unlock()
}

// pushStatus mirrors the conversion progress into the TUI status view
func (r *playlistConvertRunner) pushStatus(job *downloadJob, index int, state, detail string) {
	if r.status == nil {
		return
	}
	lines := make([]string, 0, len(job.Items))
	for i, item := range job.Items {
		labelState := item.State
		if i == index {
			labelState = state
		}
		label := fmt.Sprintf("[%s] %s - %s", labelState, item.Song.Name, item.Song.Artists)
		if i == index && detail != "" {
			label += " " + detail
		}
		lines = append(lines, label)
	}
	snap := job.snapshot()
	r.status.update(lines, snap.Done, len(snap.Items), "")
}

// scanPlaylistSources collects NCM files with parsed metadata and other encrypted files
func scanPlaylistSources(dir string, recursive bool) (map[string]ncmFileMetaInfo, []string) {
	ncmMetas := make(map[string]ncmFileMetaInfo)
	var plainFiles []string
	var paths []string
	if recursive {
		filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}
			paths = append(paths, path)
			return nil
		})
	} else {
		entries, _ := os.ReadDir(dir)
		for _, e := range entries {
			if !e.IsDir() {
				paths = append(paths, filepath.Join(dir, e.Name()))
			}
		}
	}
	for _, path := range paths {
		ext := strings.ToLower(filepath.Ext(path))
		if ext == ".ncm" {
			if meta, err := readNcmFileMeta(path); err == nil {
				ncmMetas[path] = meta
			} else {
				plainFiles = append(plainFiles, path)
			}
		} else if isQMC2Format(ext) {
			plainFiles = append(plainFiles, path)
		}
	}
	return ncmMetas, plainFiles
}

// showConvertMenu renders the local conversion submenu and returns the chosen mode
func showConvertMenu(kr *keyReader) int {
	items := []menuItem{
		{label: "默认转换", value: 1},
		{label: "歌单转换", value: 2},
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
		b.WriteString(centerLine(colorHint+"方向键 选择    Enter 确认    q 返回"+colorReset, w))
		fmt.Print(b.String())
		key := <-kr.keys
		switch key {
		case KeyArrowUp, KeyArrowLeft:
			cursor = (cursor - 1 + len(items)) % len(items)
		case KeyArrowDown, KeyArrowRight:
			cursor = (cursor + 1) % len(items)
		case KeyEnter:
			return items[cursor].value
		case KeyCtrlC:
			return -1
		case '1':
			return 1
		case '2':
			return 2
		case 'q', 'Q', KeyEsc:
			return 0
		}
	}
}

// runPlaylistConvert converts local encrypted files into a folder named after the chosen playlist
func runPlaylistConvert() {
	config := globalConfig
	initAPIConfig(config.APIConcurrent, config.APIDelayMin, config.APIDelayMax)

	inputFolder := config.InputFolder
	if inputFolder == "" || !validateDirectory(inputFolder) {
		selected, err := selectFolder("选择VipSongsDownload路径，默认路径 C:/CloudMusic/VipSongsDownload")
		if err != nil || selected == "" {
			logWarn("输入文件夹选择已取消")
			readLine(globalKeyReader, "按回车继续")
			return
		}
		inputFolder = selected
	}
	outputBase := config.OutputFolder
	if outputBase == "" {
		selected, err := selectFolder("选择保存文件夹路径")
		if err != nil || selected == "" {
			logWarn("输出文件夹选择已取消")
			readLine(globalKeyReader, "按回车继续")
			return
		}
		outputBase = selected
	}
	_ = os.MkdirAll(outputBase, 0755)

	ncmMetas, plainFiles := scanPlaylistSources(inputFolder, config.Recursive)
	if len(ncmMetas)+len(plainFiles) == 0 {
		logWarn("输入文件夹没有加密文件")
		readLine(globalKeyReader, "按回车继续")
		return
	}
	logInfo(fmt.Sprintf("扫描到 %d 个加密文件", len(ncmMetas)+len(plainFiles)))

	client := newNeteaseClient()
	status := &downloadStatus{}
	runner := newPlaylistConvertRunner(client, status, ncmMetas, plainFiles, outputBase)
	srv := newConvertWebServer(client, runner, status, webUIIndex())
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
