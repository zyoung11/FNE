//go:build windows

package main

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"
)

// apiConfig holds API rate limiting configuration
var apiConfig struct {
	concurrent int
	delayMin   int
	delayMax   int
}

var apiLimiter chan struct{}

func initAPIConfig(concurrent, delayMin, delayMax int) {
	if concurrent <= 0 {
		concurrent = 3
	}
	if delayMin < 0 {
		delayMin = 200
	}
	if delayMax < delayMin {
		delayMax = delayMin + 600
	}
	apiConfig.concurrent = concurrent
	apiConfig.delayMin = delayMin
	apiConfig.delayMax = delayMax
	apiLimiter = make(chan struct{}, concurrent)
}

// apiRequestDelay waits a random delay then acquires a rate limit slot
func apiRequestDelay() {
	delay := apiConfig.delayMin
	if apiConfig.delayMax > apiConfig.delayMin {
		delay += rand.Intn(apiConfig.delayMax - apiConfig.delayMin)
	}
	time.Sleep(time.Duration(delay) * time.Millisecond)
	apiLimiter <- struct{}{}
}

// apiRequestDone releases the rate limit slot
func apiRequestDone() {
	<-apiLimiter
}

// albumCoverCache caches album cover data by album_mid
var albumCoverCache = make(map[string][]byte)

// albumMidCache caches album_mid by song_mid
var albumMidCache = make(map[string]string)

// cacheMu guards albumCoverCache and albumMidCache for concurrent access
var cacheMu sync.Mutex

var (
	procVirtualQueryEx    = syscall.NewLazyDLL("kernel32.dll").NewProc("VirtualQueryEx")
	procReadProcessMemory = syscall.NewLazyDLL("kernel32.dll").NewProc("ReadProcessMemory")
)

// memoryBasicInformation represents the MEMORY_BASIC_INFORMATION structure
type memoryBasicInformation struct {
	BaseAddress       uintptr
	AllocationBase    uintptr
	AllocationProtect uint32
	PartitionId       uint16
	RegionSize        uintptr
	State             uint32
	Protect           uint32
	Type              uint32
}

// ============================================================
// Musicex footer parsing
// ============================================================

// MusicexInfo holds metadata extracted from a musicex footer
type MusicexInfo struct {
	SongID   uint32
	MediaMid string
	Filename string
}

// parseMusicexFooter parses the musicex footer from file data
func parseMusicexFooter(data []byte) (*MusicexInfo, error) {
	// Check for "musicex\0" magic at end
	if len(data) < 16 || string(data[len(data)-8:]) != "musicex\x00" {
		return nil, fmt.Errorf("no musicex footer found")
	}

	magicStart := len(data) - 8
	versionStart := magicStart - 4
	footerSizeStart := versionStart - 4

	if footerSizeStart < 4 {
		return nil, fmt.Errorf("musicex footer too short")
	}

	version := binary.LittleEndian.Uint32(data[versionStart:magicStart])
	footerSize := binary.LittleEndian.Uint32(data[footerSizeStart:versionStart])

	// footer_size is the total footer size including the 16-byte trailer
	metadataSize := int(footerSize) - 16
	if metadataSize <= 0 || metadataSize > int(footerSizeStart) {
		return nil, fmt.Errorf("invalid musicex footer: version=%d, footer_size=%d", version, footerSize)
	}

	if version != 1 {
		return nil, fmt.Errorf("unsupported musicex version: %d", version)
	}

	footerStart := len(data) - int(footerSize)
	meta := data[footerStart:footerSizeStart]

	// Parse the musicex metadata structure:
	// +0x00: 4 bytes song_id (uint32 LE)
	// +0x04: 4 bytes quality_type1
	// +0x08: 4 bytes quality_type2
	// +0x0C: 60 bytes media_mid (UTF-16LE, null-terminated)
	// +0x48: 68 bytes filename (UTF-16LE, null-terminated)
	var songID uint32
	if len(meta) >= 4 {
		songID = binary.LittleEndian.Uint32(meta[0:4])
	}

	mediaMid := readUTF16LEString(meta, 0x0C, 60)
	filename := readUTF16LEString(meta, 0x48, 68)

	if mediaMid == "" || filename == "" {
		return nil, fmt.Errorf("could not extract media_mid or filename from musicex footer")
	}

	return &MusicexInfo{
		SongID:   songID,
		MediaMid: mediaMid,
		Filename: filename,
	}, nil
}

// readUTF16LEString reads a null-terminated UTF-16LE string from a byte slice
func readUTF16LEString(data []byte, offset, maxLen int) string {
	end := min(offset+maxLen, len(data))

	var chars []uint16
	for i := offset; i+1 < end; i += 2 {
		code := binary.LittleEndian.Uint16(data[i : i+2])
		if code == 0 {
			break
		}
		chars = append(chars, code)
	}

	return string(utf16.Decode(chars))
}

// ============================================================
// QQ Music credentials
// ============================================================

// QQMusicCredentials holds QQ Music authentication credentials
type QQMusicCredentials struct {
	Uin    string
	Authst string
}

// getQQMusicCredentials reads QQ Music credentials from the local client
func getQQMusicCredentials() (*QQMusicCredentials, error) {
	// Read UIN from config file
	uin, err := readUINFromConfig()
	if err != nil {
		return nil, fmt.Errorf("read UIN: %w", err)
	}

	// Try to read authst from cookie files first
	authst, err := readAuthstFromCookieFiles()
	if err == nil {
		return &QQMusicCredentials{Uin: uin, Authst: authst}, nil
	}

	// Fall back to reading from process memory
	authst, err = readAuthstFromProcessMemory()
	if err != nil {
		return nil, fmt.Errorf("read authst: %w", err)
	}

	return &QQMusicCredentials{Uin: uin, Authst: authst}, nil
}

// readUINFromConfig reads the UIN from QQMusicServiceConfig.ini
func readUINFromConfig() (string, error) {
	appdata := os.Getenv("APPDATA")
	if appdata == "" {
		return "", fmt.Errorf("APPDATA environment variable not found")
	}

	configPath := filepath.Join(appdata, "Tencent", "QQMusic", "QQMusicServiceConfig.ini")
	data, err := os.ReadFile(configPath)
	if err != nil {
		return "", fmt.Errorf("read config file: %w", err)
	}

	lines := strings.SplitSeq(string(data), "\n")
	for line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToUpper(line), "UIN=") {
			uin := strings.TrimSpace(line[4:])
			if uin != "" && uin != "0" {
				return uin, nil
			}
		}
	}

	return "", fmt.Errorf("UIN not found in config")
}

// readAuthstFromCookieFiles reads authst from SetCookie.dat files
func readAuthstFromCookieFiles() (string, error) {
	appdata := os.Getenv("APPDATA")
	if appdata == "" {
		return "", fmt.Errorf("APPDATA environment variable not found")
	}

	basePath := filepath.Join(appdata, "Tencent", "QQMusic")
	filenames := []string{"SetCookie.dat", "_SetCookie.dat"}

	for _, filename := range filenames {
		path := filepath.Join(basePath, filename)
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}

		// Search for authst in JSON format
		if authst := extractAuthstFromJSON(data); authst != "" {
			return authst, nil
		}

		// Search for base64 strings
		if authst := findBestAuthst(data); authst != "" {
			return authst, nil
		}
	}

	return "", fmt.Errorf("authst not found in cookie files")
}

// extractAuthstFromJSON searches for "authst":"..." pattern in data
func extractAuthstFromJSON(data []byte) string {
	markers := [][]byte{[]byte(`"authst":"`), []byte(`"authst": "`)}
	for _, marker := range markers {
		idx := bytes.Index(data, marker)
		if idx >= 0 {
			start := idx + len(marker)
			end := bytes.IndexByte(data[start:], '"')
			if end >= 10 {
				authst := string(data[start : start+end])
				if isValidAuthst(authst) {
					return authst
				}
			}
		}
	}
	return ""
}

// findBestAuthst finds the longest base64 string in data
func findBestAuthst(data []byte) string {
	var best []byte
	var current []byte

	for _, b := range data {
		if isBase64Char(b) {
			current = append(current, b)
		} else {
			if len(current) > len(best) && len(current) >= 30 {
				best = make([]byte, len(current))
				copy(best, current)
			}
			current = nil
		}
	}

	if len(current) > len(best) && len(current) >= 30 {
		best = current
	}

	if len(best) > 0 {
		authst := string(best)
		if isValidAuthst(authst) {
			return authst
		}
	}

	return ""
}

// isBase64Char checks if a byte is a valid base64 character
func isBase64Char(b byte) bool {
	return (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') ||
		(b >= '0' && b <= '9') || b == '+' || b == '/' || b == '='
}

// isValidAuthst checks if a string looks like a valid authst
func isValidAuthst(s string) bool {
	if len(s) < 20 {
		return false
	}
	for _, c := range s {
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=' ||
			c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// readAuthstFromProcessMemory reads authst from QQMusic.exe process memory
func readAuthstFromProcessMemory() (string, error) {
	// Find QQMusic.exe process
	pids, err := findQQMusicPIDs()
	if err != nil {
		return "", fmt.Errorf("find QQ Music process: %w", err)
	}

	// Scan each process for authst
	for _, pid := range pids {
		authst, err := scanProcessForAuthst(pid)
		if err == nil && authst != "" {
			return authst, nil
		}
	}

	return "", fmt.Errorf("authst not found in QQ Music process memory - ensure QQ Music is running and logged in")
}

// findQQMusicPIDs finds all QQMusic.exe process IDs
func findQQMusicPIDs() ([]uint32, error) {
	// Use Windows API to enumerate processes
	const TH32CS_SNAPPROCESS = 0x00000002

	handle, err := syscall.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, fmt.Errorf("create snapshot: %w", err)
	}
	defer syscall.CloseHandle(handle)

	var entry syscall.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	err = syscall.Process32First(handle, &entry)
	if err != nil {
		return nil, fmt.Errorf("enumerate processes: %w", err)
	}

	var pids []uint32
	for {
		name := syscall.UTF16ToString(entry.ExeFile[:])
		if strings.EqualFold(name, "QQMusic.exe") {
			pids = append(pids, entry.ProcessID)
		}

		err = syscall.Process32Next(handle, &entry)
		if err != nil {
			break
		}
	}

	if len(pids) == 0 {
		return nil, fmt.Errorf("QQMusic.exe not found - please start QQ Music")
	}

	return pids, nil
}

// scanProcessForAuthst scans a process memory for authst string
func scanProcessForAuthst(pid uint32) (string, error) {
	const PROCESS_VM_READ = 0x0010
	const PROCESS_QUERY_INFORMATION = 0x0400
	const MEM_COMMIT = 0x1000
	const PAGE_GUARD = 0x100
	const PAGE_NOACCESS = 0x01

	// Open process
	handle, err := syscall.OpenProcess(PROCESS_VM_READ|PROCESS_QUERY_INFORMATION, false, pid)
	if err != nil {
		return "", fmt.Errorf("open process %d: %w", pid, err)
	}
	defer syscall.CloseHandle(handle)

	// Scan memory regions
	var addr uintptr
	for {
		var mbi memoryBasicInformation
		ret, _, _ := procVirtualQueryEx.Call(
			uintptr(handle),
			addr,
			uintptr(unsafe.Pointer(&mbi)),
			unsafe.Sizeof(mbi),
		)
		if ret == 0 {
			break
		}

		// Check if region is committed and readable
		if mbi.State == MEM_COMMIT &&
			mbi.Protect&PAGE_GUARD == 0 &&
			mbi.Protect&PAGE_NOACCESS == 0 &&
			mbi.RegionSize > 0 && mbi.RegionSize < 200*1024*1024 {

			// Read memory region
			buf := make([]byte, mbi.RegionSize)
			var bytesRead uintptr
			ok, _, _ := procReadProcessMemory.Call(
				uintptr(handle),
				mbi.BaseAddress,
				uintptr(unsafe.Pointer(&buf[0])),
				mbi.RegionSize,
				uintptr(unsafe.Pointer(&bytesRead)),
			)
			if ok != 0 && bytesRead > 0 {
				// Search for authst in JSON format
				if authst := extractAuthstFromJSON(buf[:bytesRead]); authst != "" {
					return authst, nil
				}
			}
		}

		// Move to next region
		addr = mbi.BaseAddress + mbi.RegionSize
		if addr == 0 || addr > 0x7FFFFFFFFFFF {
			break
		}
	}

	return "", fmt.Errorf("authst not found in process memory")
}

// ============================================================
// QQ Music API
// ============================================================

// MusicuRequest represents the request to QQ Music API
type MusicuRequest struct {
	Comm MusicuComm `json:"comm"`
	Req  MusicuReq  `json:"req_1"`
}

type MusicuComm struct {
	Authst       string `json:"authst"`
	Ct           string `json:"ct"`
	Cv           string `json:"cv"`
	Uin          string `json:"uin"`
	TmeLoginType string `json:"tmeLoginType"`
}

type MusicuReq struct {
	Module string      `json:"module"`
	Method string      `json:"method"`
	Param  MusicuParam `json:"param"`
}

type MusicuParam struct {
	Filename  []string `json:"filename"`
	Guid      string   `json:"guid"`
	Songmid   []string `json:"songmid"`
	Songtype  []int    `json:"songtype"`
	Uin       string   `json:"uin"`
	Loginflag int      `json:"loginflag"`
	Platform  string   `json:"platform"`
	Ctx       int      `json:"ctx"`
}

// MusicuResponse represents the response from QQ Music API
type MusicuResponse struct {
	Req *MusicuReqResponse `json:"req_1"`
}

type MusicuReqResponse struct {
	Code *int64      `json:"code"`
	Data *MusicuData `json:"data"`
}

type MusicuData struct {
	MidUrlInfo []MidUrlInfo `json:"midurlinfo"`
}

type MidUrlInfo struct {
	Ekey     string `json:"ekey"`
	Result   *int64 `json:"result"`
	Purl     string `json:"purl"`
	Filename string `json:"filename"`
}

// fetchEkeyFromAPI fetches the ekey from QQ Music API
func fetchEkeyFromAPI(creds *QQMusicCredentials, filename, songmid string) (string, error) {
	apiRequestDelay()
	defer apiRequestDone()
	requestBody := MusicuRequest{
		Comm: MusicuComm{
			Authst:       creds.Authst,
			Ct:           "19",
			Cv:           "1859",
			Uin:          creds.Uin,
			TmeLoginType: "3",
		},
		Req: MusicuReq{
			Module: "music.vkey.GetEVkey",
			Method: "CgiGetEVkey",
			Param: MusicuParam{
				Filename:  []string{filename},
				Guid:      "10000",
				Songmid:   []string{songmid},
				Songtype:  []int{1},
				Uin:       creds.Uin,
				Loginflag: 1,
				Platform:  "27",
				Ctx:       1,
			},
		},
	}

	jsonData, err := json.Marshal(requestBody)
	if err != nil {
		return "", fmt.Errorf("marshal request: %w", err)
	}

	client := &http.Client{}
	req, err := http.NewRequest("POST", "https://u.y.qq.com/cgi-bin/musicu.fcg", bytes.NewReader(jsonData))
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36")
	req.Header.Set("Referer", "https://y.qq.com/")

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d from QQ Music API", resp.StatusCode)
	}

	var response MusicuResponse
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return "", fmt.Errorf("decode response: %w", err)
	}

	if response.Req == nil {
		return "", fmt.Errorf("missing req_1 in API response")
	}

	if response.Req.Code == nil || *response.Req.Code != 0 {
		code := int64(-1)
		if response.Req.Code != nil {
			code = *response.Req.Code
		}
		return "", fmt.Errorf("API error (code %d)", code)
	}

	if response.Req.Data == nil || len(response.Req.Data.MidUrlInfo) == 0 {
		return "", fmt.Errorf("empty midurlinfo in API response")
	}

	info := response.Req.Data.MidUrlInfo[0]
	if info.Result != nil && *info.Result != 0 {
		return "", fmt.Errorf("API returned result code %d", *info.Result)
	}

	if info.Ekey == "" {
		return "", fmt.Errorf("empty ekey in API response")
	}

	return info.Ekey, nil
}

// fetchAlbumCover fetches the album cover image for a song
func fetchAlbumCover(songMid string) ([]byte, error) {
	cacheMu.Lock()
	albumMid, cached := albumMidCache[songMid]
	if cached {
		if cover, ok := albumCoverCache[albumMid]; ok {
			cacheMu.Unlock()
			return cover, nil
		}
		cacheMu.Unlock()
		return downloadAndCache(albumMid)
	}
	cacheMu.Unlock()

	requestBody := map[string]any{
		"comm": map[string]any{
			"ct": 19,
			"cv": 1859,
		},
		"songinfo": map[string]any{
			"method": "get_song_detail_yqq",
			"module": "music.pf_song_detail_svr",
			"param": map[string]any{
				"song_mid":  songMid,
				"song_type": 0,
			},
		},
	}

	jsonData, err := json.Marshal(requestBody)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	client := &http.Client{}
	req, err := http.NewRequest("POST", "https://u.y.qq.com/cgi-bin/musicu.fcg", bytes.NewReader(jsonData))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Mozilla/5.0")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("send request: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Code     int `json:"code"`
		Songinfo struct {
			Code int `json:"code"`
			Data struct {
				TrackInfo struct {
					Album struct {
						Mid string `json:"mid"`
					} `json:"album"`
				} `json:"track_info"`
			} `json:"data"`
		} `json:"songinfo"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	if result.Songinfo.Data.TrackInfo.Album.Mid == "" {
		return nil, fmt.Errorf("album_mid not found")
	}

	albumMid = result.Songinfo.Data.TrackInfo.Album.Mid

	cacheMu.Lock()
	albumMidCache[songMid] = albumMid
	cacheMu.Unlock()

	return downloadAndCache(albumMid)
}

// downloadAndCache downloads album cover and caches it
func downloadAndCache(albumMid string) ([]byte, error) {
	cacheMu.Lock()
	cached, ok := albumCoverCache[albumMid]
	cacheMu.Unlock()
	if ok {
		return cached, nil
	}

	coverURL := fmt.Sprintf("https://y.gtimg.cn/music/photo_new/T002R800x800M000%s.jpg", albumMid)
	resp, err := http.Get(coverURL)
	if err != nil {
		return nil, fmt.Errorf("download cover: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download cover failed: HTTP %d", resp.StatusCode)
	}

	coverData, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read cover: %w", err)
	}

	cacheMu.Lock()
	albumCoverCache[albumMid] = coverData
	cacheMu.Unlock()
	return coverData, nil
}

// ============================================================
// TC-TEA decryption
// ============================================================

// simpleMakeKey generates a simple key from a seed value
func simpleMakeKey(seed byte, size int) []byte {
	result := make([]byte, size)
	for i := range result {
		value := float64(seed) + float64(i)*0.1
		result[i] = byte(100.0 * math.Abs(math.Tan(value)))
	}
	return result
}

// deriveTEAKey derives the TEA key from the ekey header
func deriveTEAKey(ekeyHeader []byte) []byte {
	simpleKeyBuf := simpleMakeKey(106, 8)

	teaKey := make([]byte, 16)
	for i := 0; i < 16; i += 2 {
		teaKey[i] = simpleKeyBuf[i/2]
		teaKey[i+1] = ekeyHeader[i/2]
	}
	return teaKey
}

// teaDecryptECB decrypts an 8-byte block using TEA ECB mode
func teaDecryptECB(in []byte, key []byte, out []byte) {
	// Read as big-endian (network byte order)
	y := binary.BigEndian.Uint32(in[0:4])
	z := binary.BigEndian.Uint32(in[4:8])

	k := make([]uint32, 4)
	for i := range 4 {
		k[i] = binary.BigEndian.Uint32(key[i*4 : (i+1)*4])
	}

	delta := uint32(0x9E3779B9)
	sum := delta * 16

	for range 16 {
		z -= ((y << 4) + k[2]) ^ (y + sum) ^ ((y >> 5) + k[3])
		y -= ((z << 4) + k[0]) ^ (z + sum) ^ ((z >> 5) + k[1])
		sum -= delta
	}

	// Write as big-endian
	binary.BigEndian.PutUint32(out[0:4], y)
	binary.BigEndian.PutUint32(out[4:8], z)
}

// tcTeaDecrypt decrypts data using Tencent's TC-TEA algorithm (CBC mode)
// This implements oi_symmetry_decrypt2 from tc_tea.cpp
func tcTeaDecrypt(data, key []byte) ([]byte, error) {
	if len(key) != 16 {
		return nil, fmt.Errorf("TEA key must be 16 bytes")
	}

	if len(data) < 16 || len(data)%8 != 0 {
		return nil, fmt.Errorf("TEA data must be multiple of 8 bytes and at least 16 bytes")
	}

	const (
		saltLen = 2
		zeroLen = 7
	)

	// Decrypt first block
	destBuf := make([]byte, 8)
	teaDecryptECB(data[0:8], key, destBuf)

	nPadLen := int(destBuf[0] & 0x07)

	// Calculate plaintext length
	nPlainLen := len(data) - 1 - nPadLen - saltLen - zeroLen
	if nPlainLen < 0 {
		return nil, fmt.Errorf("invalid TC-TEA padding")
	}

	// Initialize IVs
	zeroBuf := make([]byte, 8)
	ivPreCrypt := zeroBuf
	ivCurCrypt := data[0:8]

	// Skip first block
	pInBuf := data[8:]
	nBufPos := 8
	destI := 1 // Skip PadLen byte

	// Skip padding
	destI += nPadLen

	// Skip salt
	for i := 1; i <= saltLen; {
		if destI < 8 {
			destI++
			i++
		} else if destI == 8 {
			// Process next block
			if len(pInBuf) < 8 {
				return nil, fmt.Errorf("invalid TC-TEA data")
			}

			ivPreCrypt = ivCurCrypt
			ivCurCrypt = pInBuf[0:8]

			// XOR with previous ciphertext
			for j := range 8 {
				destBuf[j] ^= pInBuf[j]
			}

			teaDecryptECB(destBuf, key, destBuf)

			pInBuf = pInBuf[8:]
			nBufPos += 8
			destI = 0
		}
	}

	// Extract plaintext
	result := make([]byte, 0, nPlainLen)
	for nPlainLen > 0 {
		if destI < 8 {
			result = append(result, destBuf[destI]^ivPreCrypt[destI])
			destI++
			nPlainLen--
		} else if destI == 8 {
			if len(pInBuf) < 8 {
				return nil, fmt.Errorf("invalid TC-TEA data")
			}

			ivPreCrypt = ivCurCrypt
			ivCurCrypt = pInBuf[0:8]

			for j := range 8 {
				destBuf[j] ^= pInBuf[j]
			}

			teaDecryptECB(destBuf, key, destBuf)

			pInBuf = pInBuf[8:]
			nBufPos += 8
			destI = 0
		}
	}

	// Verify zero padding
	for i := 1; i <= zeroLen; {
		if destI < 8 {
			if destBuf[destI]^ivPreCrypt[destI] != 0 {
				return nil, fmt.Errorf("invalid TC-TEA zero padding")
			}
			destI++
			i++
		} else if destI == 8 {
			if len(pInBuf) < 8 {
				break
			}

			ivPreCrypt = ivCurCrypt
			ivCurCrypt = pInBuf[0:8]

			for j := range 8 {
				destBuf[j] ^= pInBuf[j]
			}

			teaDecryptECB(destBuf, key, destBuf)

			pInBuf = pInBuf[8:]
			nBufPos += 8
			destI = 0
		}
	}

	return result, nil
}

// parseEkey parses an ekey string and derives the raw decryption key
func parseEkey(ekey string) ([]byte, error) {
	ekey = strings.TrimRight(ekey, "\x00")

	ekeyDecoded, err := base64.StdEncoding.DecodeString(ekey)
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %w", err)
	}

	if len(ekeyDecoded) < 8 {
		return nil, fmt.Errorf("decoded key too short (%d bytes)", len(ekeyDecoded))
	}

	// Check for EncV2 prefix
	encv2Prefix := []byte("QQMusic EncV2,Key:")
	if bytes.HasPrefix(ekeyDecoded, encv2Prefix) {
		encv2Blob := ekeyDecoded[len(encv2Prefix):]
		encv2Stage1Key := []byte("386ZJY!@#*$%^&)(")
		encv2Stage2Key := []byte("**#!(#$%&^a1cZ,T")

		stage1, err := tcTeaDecrypt(encv2Blob, encv2Stage1Key)
		if err != nil {
			return nil, fmt.Errorf("EncV2 stage 1 decrypt: %w", err)
		}

		stage2, err := tcTeaDecrypt(stage1, encv2Stage2Key)
		if err != nil {
			return nil, fmt.Errorf("EncV2 stage 2 decrypt: %w", err)
		}

		ekeyDecoded, err = base64.StdEncoding.DecodeString(string(stage2))
		if err != nil {
			return nil, fmt.Errorf("EncV2 base64 decode: %w", err)
		}
	}

	if len(ekeyDecoded) < 8 {
		return nil, fmt.Errorf("decoded key too short after EncV2 processing")
	}

	// Try EncV1 parsing
	header := ekeyDecoded[:8]
	body := ekeyDecoded[8:]

	if len(body) == 0 {
		return header, nil
	}

	// Derive TEA key from header
	teaKey := deriveTEAKey(header)

	// Try TC-TEA decryption
	decryptedBody, err := tcTeaDecrypt(body, teaKey)
	if err == nil {
		// Successfully decrypted EncV1 format
		result := make([]byte, 8+len(decryptedBody))
		copy(result[:8], header)
		copy(result[8:], decryptedBody)
		return result, nil
	}

	// TC-TEA decryption failed - use raw key
	return ekeyDecoded, nil
}

// ============================================================
// QMC2 decryption
// ============================================================

// qmc2MapDecrypt decrypts data using QMC2 Map cipher (for key length <= 300)
func qmc2MapDecrypt(key []byte, offset int, buf []byte) {
	keyLen := len(key)
	for i := range buf {
		offsetLocal := offset + i
		if offsetLocal > 0x7FFF {
			offsetLocal %= 0x7FFF
		}
		index := (offsetLocal*offsetLocal + 71214) % keyLen
		buf[i] ^= scrambleByIndex(key[index], index)
	}
}

// scrambleByIndex scrambles a key byte by its index (bit rotation)
func scrambleByIndex(value byte, index int) byte {
	rotation := (index + 4) & 7
	left := value << rotation
	right := value >> (8 - rotation)
	return left | right
}

// qmc2Rc4Decrypt decrypts data using QMC2 RC4 cipher (for key length > 300)
type qmc2Rc4Crypto struct {
	s      []byte
	hash   uint32
	rc4Key []byte
}

func newQmc2Rc4Crypto(rc4Key []byte) *qmc2Rc4Crypto {
	n := len(rc4Key)

	// Initialize S-box
	// QMC2 RC4 uses a variable-size S-box equal to the key length.
	// For key lengths > 255, we use the full key length as the S-box size.
	// Standard RC4 uses 256, but QMC2 uses the key length.
	s := make([]byte, n)
	for i := range s {
		s[i] = byte(i & 0xFF)
	}

	// KSA (Key Scheduling Algorithm)
	j := 0
	for i := range n {
		j = (j + int(s[i]) + int(rc4Key[i])) % n
		s[i], s[j] = s[j], s[i]
	}

	return &qmc2Rc4Crypto{
		s:      s,
		hash:   calcHashBase(rc4Key),
		rc4Key: rc4Key,
	}
}

func calcHashBase(data []byte) uint32 {
	hash := uint32(1)
	for _, value := range data {
		if value == 0 {
			continue
		}
		nextHash := hash * uint32(value)
		if nextHash == 0 || nextHash <= hash {
			break
		}
		hash = nextHash
	}
	return hash
}

func (c *qmc2Rc4Crypto) calcSegmentKey(id uint64, seed uint64) uint64 {
	dividend := float64(c.hash)
	divisor := float64((id + 1) * seed)
	if divisor == 0 {
		divisor = 1
	}
	key := dividend / divisor * 100.0
	return uint64(key)
}

func (c *qmc2Rc4Crypto) rc4Derive(n int, s []byte, j, k *int) byte {
	*j = (*j + 1) % n
	*k = (int(s[*j]) + *k) % n
	s[*j], s[*k] = s[*k], s[*j]
	index := int(s[*j]) + int(s[*k])
	return s[index%n]
}

const (
	firstSegmentSize = 0x80
	otherSegmentSize = 0x1400
)

func (c *qmc2Rc4Crypto) encodeFirstSegment(offset int, buf []byte) {
	n := len(c.rc4Key)
	for i := range buf {
		key1 := uint64(c.rc4Key[offset%n])
		key2 := c.calcSegmentKey(uint64(offset), key1)
		buf[i] ^= c.rc4Key[key2%uint64(n)]
		offset++
	}
}

func (c *qmc2Rc4Crypto) encodeOtherSegment(offset int, buf []byte) {
	segID := uint64(offset / otherSegmentSize)
	segIDSmall := segID & 0x1FF

	discardCount := c.calcSegmentKey(segID, uint64(c.rc4Key[segIDSmall])) & 0x1FF
	discardCount += uint64(offset % otherSegmentSize)

	n := len(c.rc4Key)
	s := make([]byte, n)
	copy(s, c.s)
	j := 0
	k := 0
	for i := uint64(0); i < discardCount; i++ {
		c.rc4Derive(n, s, &j, &k)
	}

	for i := range buf {
		buf[i] ^= c.rc4Derive(n, s, &j, &k)
	}
}

func (c *qmc2Rc4Crypto) decrypt(offset int, buf []byte) {
	i := 0
	remaining := len(buf)

	// First segment has a different algorithm
	if offset < firstSegmentSize {
		processed := min(remaining, firstSegmentSize-offset)
		c.encodeFirstSegment(offset, buf[i:i+processed])
		i += processed
		remaining -= processed
		offset += processed
	}

	// Align to segment boundary
	toAlign := offset % otherSegmentSize
	if toAlign != 0 && remaining > 0 {
		processed := min(remaining, otherSegmentSize-toAlign)
		c.encodeOtherSegment(offset, buf[i:i+processed])
		i += processed
		remaining -= processed
		offset += processed
	}

	// Process full segments
	for remaining > otherSegmentSize {
		c.encodeOtherSegment(offset, buf[i:i+otherSegmentSize])
		i += otherSegmentSize
		remaining -= otherSegmentSize
		offset += otherSegmentSize
	}

	// Remaining bytes
	if remaining > 0 {
		c.encodeOtherSegment(offset, buf[i:i+remaining])
	}
}

// ============================================================
// QMC2 conversion
// ============================================================

// getOutputFormat returns the output format based on input extension
func getOutputFormat(ext string) string {
	switch ext {
	case ".mflac", ".mflac0", ".mflach":
		return "flac"
	case ".mgg", ".mgg0", ".mgg1", ".mggl":
		return "ogg"
	}
	return "flac" // default
}

// convertQMC2File converts a QMC2 encrypted file (mflac/mgg) to its original format
func convertQMC2File(inputPath, outputDir string) (string, error) {
	var ekey string
	inputExt := strings.ToLower(filepath.Ext(inputPath))

	// Read the entire file
	data, err := os.ReadFile(inputPath)
	if err != nil {
		return "", fmt.Errorf("read file: %w", err)
	}

	// Parse musicex footer
	info, err := parseMusicexFooter(data)
	if err != nil {
		return "", fmt.Errorf("parse musicex footer: %w", err)
	}

	// If no ekey provided, try to fetch from API
	if ekey == "" {
		creds, err := getQQMusicCredentials()
		if err != nil {
			return "", fmt.Errorf("get QQ Music credentials: %w", err)
		}

		// Ensure filename has proper extension
		apiFilename := info.Filename
		if !isQMC2Format(filepath.Ext(apiFilename)) {
			// Use the input file's extension
			apiFilename = apiFilename + inputExt
		}

		ekey, err = fetchEkeyFromAPI(creds, apiFilename, info.MediaMid)
		if err != nil {
			return "", fmt.Errorf("fetch ekey: %w", err)
		}
	}

	// Parse ekey to get decryption key
	key, err := parseEkey(ekey)
	if err != nil {
		return "", fmt.Errorf("parse ekey: %w", err)
	}

	// Find where audio data starts (after musicex footer)
	footerSize := uint32(0xC0) // Default footer size
	if len(data) >= 16 {
		footerSize = binary.LittleEndian.Uint32(data[len(data)-16 : len(data)-12])
	}
	audioEnd := len(data) - int(footerSize)
	if audioEnd <= 0 {
		return "", fmt.Errorf("invalid footer size")
	}

	// Decrypt audio data
	audioData := make([]byte, audioEnd)
	copy(audioData, data[:audioEnd])

	if len(key) > 300 {
		// Use RC4 cipher
		crypto := newQmc2Rc4Crypto(key)
		crypto.decrypt(0, audioData)
	} else {
		// Use Map cipher
		qmc2MapDecrypt(key, 0, audioData)
	}

	// Determine output format based on input extension
	outputExt := getOutputFormat(inputExt)
	baseName := strings.TrimSuffix(filepath.Base(inputPath), filepath.Ext(inputPath))
	outputPath := filepath.Join(outputDir, baseName+"."+outputExt)

	if err := os.WriteFile(outputPath, audioData, 0644); err != nil {
		return "", fmt.Errorf("write output: %w", err)
	}

	// Fetch and embed album cover (only for FLAC for now)
	if outputExt == "flac" {
		coverData, err := fetchAlbumCover(info.MediaMid)
		if err == nil && len(coverData) > 0 {
			embedFLACCover(outputPath, coverData)
		}
	}

	preserveCreationTime(inputPath, outputPath)
	return outputExt, nil
}

// detectAudioFormat detects the audio format from the data header
func detectAudioFormat(data []byte) string {
	if len(data) >= 4 {
		// Check for FLAC
		if string(data[:4]) == "fLaC" {
			return "flac"
		}
		// Check for OGG
		if string(data[:4]) == "OggS" {
			return "ogg"
		}
		// Check for MP3
		if len(data) >= 3 && data[0] == 0xFF && (data[1]&0xE0) == 0xE0 {
			return "mp3"
		}
	}
	return "bin"
}
