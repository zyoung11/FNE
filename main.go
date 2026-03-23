package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	_ "embed"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/schollz/progressbar/v3"
)

//go:embed ffmpeg.exe
var ffmpegExe []byte

type ncmMetadata struct {
	MusicName string          `json:"musicName"`
	Album     string          `json:"album"`
	Artist    json.RawMessage `json:"artist"`
	Format    string          `json:"format"`
}

type ecb struct {
	b         cipher.Block
	blockSize int
}

func newECB(b cipher.Block) *ecb {
	return &ecb{b: b, blockSize: b.BlockSize()}
}

func (x *ecb) Decrypt(dst, src []byte) {
	if len(src)%x.blockSize != 0 {
		panic("crypto/cipher: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("crypto/cipher: output smaller than input")
	}
	for len(src) > 0 {
		x.b.Decrypt(dst, src[:x.blockSize])
		src = src[x.blockSize:]
		dst = dst[x.blockSize:]
	}
}

func unpad(src []byte) []byte {
	length := len(src)
	if length == 0 {
		return src
	}
	unpadding := int(src[length-1])
	if unpadding > length {
		return src
	}
	return src[:length-unpadding]
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic("invalid hex constant: " + s)
	}
	return b
}

func newAESCipher(key []byte) cipher.Block {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic("aes.NewCipher failed: " + err.Error())
	}
	return block
}

func parseArtist(raw json.RawMessage) string {
	if len(raw) == 0 || string(raw) == "null" {
		return "Unknown Artist"
	}

	var nested [][]string
	if err := json.Unmarshal(raw, &nested); err == nil {
		var names []string
		for _, a := range nested {
			if len(a) > 0 {
				names = append(names, a[0])
			}
		}
		return strings.Join(names, "/")
	}

	var mixed []interface{}
	if err := json.Unmarshal(raw, &mixed); err == nil {
		var names []string
		for _, v := range mixed {
			switch val := v.(type) {
			case string:
				names = append(names, val)
			case float64:
				names = append(names, fmt.Sprintf("%.0f", val))
			}
		}
		return strings.Join(names, "/")
	}

	var single interface{}
	if err := json.Unmarshal(raw, &single); err == nil {
		switch val := single.(type) {
		case string:
			return val
		case float64:
			return fmt.Sprintf("%.0f", val)
		}
	}

	return "Unknown Artist"
}

func extractFFmpeg() (string, error) {
	tmp, err := os.CreateTemp("", "ffmpeg-*.exe")
	if err != nil {
		return "", err
	}
	if _, err := tmp.Write(ffmpegExe); err != nil {
		tmp.Close()
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	return tmp.Name(), nil
}

var (
	coreKey = mustHex("687A4852416D736F356B496E62617857")
	metaKey = mustHex("2331346C6A6B5F215C5D2630553C2728")
)

func convertNcmFile(inputPath, outputDir string) error {
	file, err := os.Open(inputPath)
	if err != nil {
		return fmt.Errorf("open ncm file: %w", err)
	}
	defer file.Close()

	header := make([]byte, 8)
	if _, err := io.ReadFull(file, header); err != nil {
		return fmt.Errorf("read header: %w", err)
	}
	if string(header) != "CTENFDAM" {
		return errors.New("invalid ncm file header")
	}
	if _, err := file.Seek(2, io.SeekCurrent); err != nil {
		return fmt.Errorf("seek: %w", err)
	}

	var keyLength uint32
	if err := binary.Read(file, binary.LittleEndian, &keyLength); err != nil {
		return fmt.Errorf("read key length: %w", err)
	}
	keyDataEnc := make([]byte, keyLength)
	if _, err := io.ReadFull(file, keyDataEnc); err != nil {
		return fmt.Errorf("read key data: %w", err)
	}
	for i := range keyDataEnc {
		keyDataEnc[i] ^= 0x64
	}
	block := newAESCipher(coreKey)
	ecbDec := newECB(block)
	keyDataPadded := make([]byte, len(keyDataEnc))
	ecbDec.Decrypt(keyDataPadded, keyDataEnc)
	keyData := unpad(keyDataPadded)[17:]

	keyBox := make([]byte, 256)
	for i := range keyBox {
		keyBox[i] = byte(i)
	}
	c, lastByte, keyOffset := byte(0), byte(0), 0
	for i := 0; i < 256; i++ {
		c = keyBox[i] + lastByte + keyData[keyOffset]
		keyOffset = (keyOffset + 1) % len(keyData)
		keyBox[i], keyBox[c] = keyBox[c], keyBox[i]
		lastByte = c
	}

	var metaLength uint32
	if err := binary.Read(file, binary.LittleEndian, &metaLength); err != nil {
		return fmt.Errorf("read meta length: %w", err)
	}
	metaDataEnc := make([]byte, metaLength)
	if _, err := io.ReadFull(file, metaDataEnc); err != nil {
		return fmt.Errorf("read meta data: %w", err)
	}
	for i := range metaDataEnc {
		metaDataEnc[i] ^= 0x63
	}
	metaDataB64, err := base64.StdEncoding.DecodeString(string(metaDataEnc[22:]))
	if err != nil {
		return fmt.Errorf("base64 decode metadata: %w", err)
	}
	block = newAESCipher(metaKey)
	ecbDec = newECB(block)
	metaDataPadded := make([]byte, len(metaDataB64))
	ecbDec.Decrypt(metaDataPadded, metaDataB64)
	metaDataJson := unpad(metaDataPadded)[6:]

	var meta ncmMetadata
	if err := json.Unmarshal(metaDataJson, &meta); err != nil {
		return fmt.Errorf("unmarshal metadata: %w", err)
	}
	if _, err := file.Seek(9, io.SeekCurrent); err != nil {
		return fmt.Errorf("seek to image: %w", err)
	}

	var imageSize uint32
	if err := binary.Read(file, binary.LittleEndian, &imageSize); err != nil {
		return fmt.Errorf("read image size: %w", err)
	}
	imageData := make([]byte, imageSize)
	if _, err := io.ReadFull(file, imageData); err != nil {
		return fmt.Errorf("read image data: %w", err)
	}

	tempAudio, err := os.CreateTemp("", fmt.Sprintf("ncm-audio-*.%s", strings.ToLower(meta.Format)))
	if err != nil {
		return fmt.Errorf("create temp audio: %w", err)
	}
	defer os.Remove(tempAudio.Name())

	hasValidImage := len(imageData) > 0 &&
		(bytes.HasPrefix(imageData, []byte{0xFF, 0xD8}) ||
			bytes.HasPrefix(imageData, []byte{0x89, 0x50}))

	var tempImagePath string
	if hasValidImage {
		tmpImg, err := os.CreateTemp("", "ncm-cover-*.jpg")
		if err != nil {
			return fmt.Errorf("create temp image: %w", err)
		}
		if _, err := tmpImg.Write(imageData); err != nil {
			tmpImg.Close()
			return fmt.Errorf("write temp image: %w", err)
		}
		tmpImg.Close()
		tempImagePath = tmpImg.Name()
		defer os.Remove(tempImagePath)
	}

	chunk := make([]byte, 0x8000)
	for {
		n, err := file.Read(chunk)
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read audio chunk: %w", err)
		}
		for i := 0; i < n; i++ {
			j := byte(i + 1)
			chunk[i] ^= keyBox[(keyBox[j]+keyBox[(keyBox[j]+j)&0xff])&0xff]
		}
		if _, err := tempAudio.Write(chunk[:n]); err != nil {
			return fmt.Errorf("write audio chunk: %w", err)
		}
	}
	tempAudio.Close()

	baseName := strings.TrimSuffix(filepath.Base(inputPath), filepath.Ext(inputPath))
	outputPath := filepath.Join(outputDir, baseName+"."+meta.Format)
	artistsStr := parseArtist(meta.Artist)

	var args []string
	if hasValidImage {
		args = []string{
			"-y",
			"-i", tempAudio.Name(),
			"-i", tempImagePath,
			"-map", "0:a", "-map", "1:v",
			"-c", "copy",
			"-disposition:v", "attached_pic",
			"-metadata", "title=" + meta.MusicName,
			"-metadata", "artist=" + artistsStr,
			"-metadata", "album=" + meta.Album,
			outputPath,
		}
	} else {
		args = []string{
			"-y",
			"-i", tempAudio.Name(),
			"-c", "copy",
			"-metadata", "title=" + meta.MusicName,
			"-metadata", "artist=" + artistsStr,
			"-metadata", "album=" + meta.Album,
			outputPath,
		}
	}

	ffmpegPath, err := extractFFmpeg()
	if err != nil {
		return fmt.Errorf("extract ffmpeg: %w", err)
	}
	defer os.Remove(ffmpegPath)
	cmd := exec.Command(ffmpegPath, args...)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("ffmpeg failed: %w\n%s", err, string(output))
	}

	return nil
}

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
		if ext == ".mp3" || ext == ".flac" {
			name := strings.TrimSuffix(e.Name(), ext)
			set[name] = struct{}{}
		}
	}
	return set
}

// --- Windows COM API for folder selection ---

var (
	user32             = syscall.NewLazyDLL("user32.dll")
	ole32              = syscall.NewLazyDLL("ole32.dll")
	setProcessDPIAware = user32.NewProc("SetProcessDPIAware")
	coInitializeEx     = ole32.NewProc("CoInitializeEx")
	coUninitialize     = ole32.NewProc("CoUninitialize")
	coCreateInstance   = ole32.NewProc("CoCreateInstance")
	coTaskMemFree      = ole32.NewProc("CoTaskMemFree")
)

type GUID struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]byte
}

var (
	CLSID_FileOpenDialog = GUID{0xDC1C5A9C, 0xE88A, 0x4DDE, [8]byte{0xA5, 0xA1, 0x60, 0xF8, 0x2A, 0x20, 0xAE, 0xF7}}
	IID_IFileDialog      = GUID{0x42F85136, 0xDB7E, 0x439C, [8]byte{0x85, 0xF1, 0xE4, 0x07, 0x5D, 0x13, 0x5F, 0xC8}}
)

type IFileDialogVtbl struct {
	QueryInterface      uintptr
	AddRef              uintptr
	Release             uintptr
	Show                uintptr
	SetFileTypes        uintptr
	SetFileTypeIndex    uintptr
	GetFileTypeIndex    uintptr
	Advise              uintptr
	Unadvise            uintptr
	SetOptions          uintptr
	GetOptions          uintptr
	SetDefaultFolder    uintptr
	SetFolder           uintptr
	GetFolder           uintptr
	GetCurrentSelection uintptr
	SetFileName         uintptr
	GetFileName         uintptr
	SetTitle            uintptr
	SetOkButtonLabel    uintptr
	SetFileNameLabel    uintptr
	GetResult           uintptr
	AddPlace            uintptr
	SetDefaultExtension uintptr
	Close               uintptr
	SetClientGuid       uintptr
	ClearClientData     uintptr
	SetFilter           uintptr
}

type IFileDialog struct{ lpVtbl *IFileDialogVtbl }

type IShellItemVtbl struct {
	QueryInterface uintptr
	AddRef         uintptr
	Release        uintptr
	BindToHandler  uintptr
	GetParent      uintptr
	GetDisplayName uintptr
	GetAttributes  uintptr
	Compare        uintptr
}

type IShellItem struct{ lpVtbl *IShellItemVtbl }

const (
	FOS_PICKFOLDERS          = 0x00000020
	COINIT_APARTMENTTHREADED = 0x2
	SIGDN_FILESYSPATH        = 0x80028000
)

func init() { setProcessDPIAware.Call() }

func utf16PtrToString(p *uint16) string {
	if p == nil {
		return ""
	}
	end := unsafe.Pointer(p)
	n := 0
	for *(*uint16)(end) != 0 {
		end = unsafe.Pointer(uintptr(end) + unsafe.Sizeof(*p))
		n++
	}
	s := make([]uint16, n)
	ptr := unsafe.Pointer(p)
	for i := 0; i < n; i++ {
		s[i] = *(*uint16)(ptr)
		ptr = unsafe.Pointer(uintptr(ptr) + unsafe.Sizeof(*p))
	}
	return syscall.UTF16ToString(s)
}

func (obj *IFileDialog) Release() uint32 {
	ret, _, _ := syscall.SyscallN(obj.lpVtbl.Release, uintptr(unsafe.Pointer(obj)))
	return uint32(ret)
}

func (obj *IShellItem) Release() uint32 {
	ret, _, _ := syscall.SyscallN(obj.lpVtbl.Release, uintptr(unsafe.Pointer(obj)))
	return uint32(ret)
}

func selectFolder(title string) (string, error) {
	hr, _, _ := syscall.SyscallN(coInitializeEx.Addr(), 0, COINIT_APARTMENTTHREADED)
	if int32(hr) < 0 {
		return "", errors.New("COM initialization failed")
	}
	defer syscall.SyscallN(coUninitialize.Addr())

	var pDialog *IFileDialog
	hr, _, _ = syscall.SyscallN(
		coCreateInstance.Addr(),
		uintptr(unsafe.Pointer(&CLSID_FileOpenDialog)), 0, 1,
		uintptr(unsafe.Pointer(&IID_IFileDialog)),
		uintptr(unsafe.Pointer(&pDialog)),
	)
	if int32(hr) < 0 {
		return "", errors.New("create FileOpenDialog failed")
	}
	defer pDialog.Release()

	hr, _, _ = syscall.SyscallN(
		pDialog.lpVtbl.SetOptions,
		uintptr(unsafe.Pointer(pDialog)), FOS_PICKFOLDERS,
	)
	if int32(hr) < 0 {
		return "", errors.New("set options failed")
	}

	titlePtr, err := syscall.UTF16PtrFromString(title)
	if err != nil {
		return "", fmt.Errorf("convert title: %w", err)
	}
	hr, _, _ = syscall.SyscallN(
		pDialog.lpVtbl.SetTitle,
		uintptr(unsafe.Pointer(pDialog)),
		uintptr(unsafe.Pointer(titlePtr)),
	)
	if int32(hr) < 0 {
		return "", errors.New("set title failed")
	}

	hr, _, _ = syscall.SyscallN(
		pDialog.lpVtbl.Show, uintptr(unsafe.Pointer(pDialog)), 0,
	)
	if int32(hr) < 0 {
		return "", errors.New("user cancelled")
	}

	var pItem *IShellItem
	hr, _, _ = syscall.SyscallN(
		pDialog.lpVtbl.GetResult,
		uintptr(unsafe.Pointer(pDialog)),
		uintptr(unsafe.Pointer(&pItem)),
	)
	if int32(hr) < 0 {
		return "", errors.New("get result failed")
	}
	defer pItem.Release()

	var pszPath *uint16
	hr, _, _ = syscall.SyscallN(
		pItem.lpVtbl.GetDisplayName,
		uintptr(unsafe.Pointer(pItem)), SIGDN_FILESYSPATH,
		uintptr(unsafe.Pointer(&pszPath)),
	)
	if int32(hr) < 0 {
		return "", errors.New("get display name failed")
	}
	defer syscall.SyscallN(coTaskMemFree.Addr(), uintptr(unsafe.Pointer(pszPath)))

	return utf16PtrToString(pszPath), nil
}

// --- Main ---

func main() {
	inputFolder, err := selectFolder("选择VipSongsDownload路径，默认路径：C:/CloudMusic/VipSongsDownload")
	if err != nil || inputFolder == "" {
		fmt.Println("Input folder selection cancelled:", err)
		os.Exit(0)
	}
	outputFolder, err := selectFolder("选择保存文件夹路径")
	if err != nil || outputFolder == "" {
		fmt.Println("Output folder selection cancelled:", err)
		os.Exit(0)
	}

	if _, err := os.Stat(inputFolder); os.IsNotExist(err) {
		fmt.Printf("Input folder does not exist: %s\n", inputFolder)
		os.Exit(1)
	}
	_ = os.MkdirAll(outputFolder, 0755)

	entries, err := os.ReadDir(inputFolder)
	if err != nil {
		fmt.Printf("Read input folder error: %v\n", err)
		os.Exit(1)
	}

	existing := buildExistingFileSet(outputFolder)

	var ncmListOriginal, ncmList []string
	for _, e := range entries {
		if e.IsDir() || !strings.EqualFold(filepath.Ext(e.Name()), ".ncm") {
			continue
		}
		ncmListOriginal = append(ncmListOriginal, filepath.Join(inputFolder, e.Name()))
		baseName := strings.TrimSuffix(e.Name(), filepath.Ext(e.Name()))
		if _, found := existing[baseName]; !found {
			ncmList = append(ncmList, filepath.Join(inputFolder, e.Name()))
		}
	}

	if len(ncmListOriginal) == 0 {
		fmt.Println("No .ncm files found.")
		os.Exit(0)
	}
	total := len(ncmList)
	if total == 0 {
		fmt.Println("All files already converted.")
		os.Exit(0)
	}

	skipped := len(ncmListOriginal) - total
	if skipped > 0 {
		fmt.Printf("Skipped %d already converted files.\n", skipped)
	}

	bar := progressbar.NewOptions(total,
		progressbar.OptionEnableColorCodes(true),
		progressbar.OptionShowBytes(false),
		progressbar.OptionSetWidth(50),
		progressbar.OptionSetDescription("Converting..."),
		progressbar.OptionSetTheme(progressbar.Theme{
			Saucer:        "[green]█[reset]",
			SaucerHead:    "[green]>[reset]",
			SaucerPadding: " ",
			BarStart:      "[",
			BarEnd:        "]",
		}),
		progressbar.OptionOnCompletion(func() { fmt.Println() }),
	)

	success, failed := 0, 0
	start := time.Now()
	const workerCount = 8

	jobs := make(chan string, total)
	var wg sync.WaitGroup
	var mu sync.Mutex

	for w := 0; w < workerCount; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for path := range jobs {
				err := convertNcmFile(path, outputFolder)
				mu.Lock()
				if err != nil {
					failed++
				} else {
					success++
				}
				mu.Unlock()
				if err != nil {
					fmt.Fprintf(os.Stderr, "[FAIL] %s : %v\n", filepath.Base(path), err)
				}
				bar.Add(1)
			}
		}()
	}

	for _, path := range ncmList {
		jobs <- path
	}
	close(jobs)
	wg.Wait()

	elapsed := time.Since(start)
	fmt.Printf("Done!  Success: %d , Failed: %d , Time: %.1fs\n", success, failed, elapsed.Seconds())
}
