package main

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/skip2/go-qrcode"
)

// webUIHTML is the embedded single page UI served to the browser
//
//go:embed webui/index.html
var webUIHTML string

// webServer hosts the browser UI for the online download mode
type webServer struct {
	client *neteaseClient
	dl     *downloader
	status *downloadStatus
	html   string
	mu     sync.Mutex
	srv    *http.Server
	port   int
}

// newWebServer prepares the API routes for the download mode
func newWebServer(client *neteaseClient, dl *downloader, status *downloadStatus, html string) *webServer {
	return &webServer{client: client, dl: dl, status: status, html: html}
}

// Start binds a random local port and serves the UI in the background
func (s *webServer) Start() (int, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	s.port = listener.Addr().(*net.TCPAddr).Port
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.handleIndex)
	mux.HandleFunc("GET /api/status", s.handleStatus)
	mux.HandleFunc("POST /api/login/qr", s.handleLoginQR)
	mux.HandleFunc("GET /api/login/check", s.handleLoginCheck)
	mux.HandleFunc("GET /api/qr.png", s.handleQRImage)
	mux.HandleFunc("GET /api/search", s.handleSearch)
	mux.HandleFunc("GET /api/album", s.handleAlbum)
	mux.HandleFunc("POST /api/check", s.handleCheck)
	mux.HandleFunc("POST /api/download", s.handleDownload)
	mux.HandleFunc("GET /api/job", s.handleJob)
	mux.HandleFunc("POST /api/pick-folder", s.handlePickFolder)
	s.srv = &http.Server{Handler: mux}
	go s.srv.Serve(listener)
	return s.port, nil
}

// Stop shuts the HTTP server down
func (s *webServer) Stop() {
	s.mu.Lock()
	srv := s.srv
	s.mu.Unlock()
	if srv != nil {
		srv.Close()
	}
}

// writeJSON serializes a response object as JSON
func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(v)
}

// writeError serializes an error response
func writeError(w http.ResponseWriter, status int, msg string) {
	w.WriteHeader(status)
	writeJSON(w, map[string]any{"error": msg})
}

// handleIndex serves the embedded single page UI with the correct initial view
func (s *webServer) handleIndex(w http.ResponseWriter, r *http.Request) {
	html := s.html
	if s.client.LoggedIn() {
		html = strings.ReplaceAll(html, "{{INIT_LOGIN}}", "")
		html = strings.ReplaceAll(html, "{{INIT_SEARCH}}", " active")
	} else {
		html = strings.ReplaceAll(html, "{{INIT_LOGIN}}", " active")
		html = strings.ReplaceAll(html, "{{INIT_SEARCH}}", "")
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, html)
}

// handleStatus reports the login state, platform and the default save folder
func (s *webServer) handleStatus(w http.ResponseWriter, r *http.Request) {
	resp := map[string]any{
		"loggedIn":      s.client.LoggedIn(),
		"defaultFolder": defaultDownloadFolder(),
		"platform":      runtimePlatform(),
		"cookiePath":    s.client.CookieFilePath(),
	}
	if s.client.LoggedIn() {
		if nickname, err := s.client.Account(); err == nil {
			resp["nickname"] = nickname
		}
	}
	writeJSON(w, resp)
}

// handleLoginQR creates a new QR login key
func (s *webServer) handleLoginQR(w http.ResponseWriter, r *http.Request) {
	key, err := s.client.LoginQRKey()
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	s.client.Save()
	writeJSON(w, map[string]any{"key": key, "url": s.client.LoginQRURL(key)})
}

// handleLoginCheck polls the QR login status
func (s *webServer) handleLoginCheck(w http.ResponseWriter, r *http.Request) {
	key := r.URL.Query().Get("key")
	code, err := s.client.LoginQRCheck(key)
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	resp := map[string]any{"code": code}
	if code == 803 {
		saved := s.client.Save() == nil
		resp["saved"] = saved
		if nickname, err := s.client.Account(); err == nil {
			resp["nickname"] = nickname
		}
	}
	writeJSON(w, resp)
}

// handleQRImage renders the login QR code as a PNG image
func (s *webServer) handleQRImage(w http.ResponseWriter, r *http.Request) {
	key := r.URL.Query().Get("key")
	png, err := qrcode.Encode(s.client.LoginQRURL(key), qrcode.Medium, 320)
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Write(png)
}

// handleSearch runs a song or album search
func (s *webServer) handleSearch(w http.ResponseWriter, r *http.Request) {
	keyword := r.URL.Query().Get("kw")
	kind := r.URL.Query().Get("type")
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
	if limit <= 0 {
		limit = 20
	}
	if kind == "album" {
		albums, total, err := s.client.SearchAlbums(keyword, limit, offset)
		if err != nil {
			writeError(w, 500, err.Error())
			return
		}
		writeJSON(w, map[string]any{"type": "album", "total": total, "albums": albums})
		return
	}
	songs, total, err := s.client.SearchSongs(keyword, limit, offset)
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, map[string]any{"type": "song", "total": total, "songs": songs})
}

// handleAlbum returns album metadata with its tracks
func (s *webServer) handleAlbum(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.URL.Query().Get("id"), 10, 64)
	album, songs, err := s.client.AlbumDetail(id)
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, map[string]any{"album": album, "songs": songs})
}

// handleCheck reports the real quality levels each selected song offers to the current account
func (s *webServer) handleCheck(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Songs []songItem `json:"songs"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	type checkResult struct {
		ID     int64    `json:"id"`
		Levels []string `json:"levels"`
		Top    string   `json:"top"`
		Type   string   `json:"type"`
		OK     bool     `json:"ok"`
	}
	ids := make([]int64, 0, len(req.Songs))
	for _, song := range req.Songs {
		ids = append(ids, song.ID)
	}
	qualities, err := s.client.SongQualities(ids)
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	results := make([]checkResult, 0, len(req.Songs))
	for _, song := range req.Songs {
		q := qualities[song.ID]
		results = append(results, checkResult{ID: song.ID, Levels: q.Levels, Top: q.Top, Type: q.Type, OK: len(q.Levels) > 0})
	}
	writeJSON(w, map[string]any{"results": results})
}

// handleDownload starts a download job for the selected songs
func (s *webServer) handleDownload(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Folder string         `json:"folder"`
		Items  []downloadItem `json:"items"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	if len(req.Items) == 0 {
		writeError(w, 400, "no songs selected")
		return
	}
	if req.Folder == "" {
		writeError(w, 400, "no folder selected")
		return
	}
	for i := range req.Items {
		if req.Items[i].Level == "" {
			req.Items[i].Level = "hires"
		}
	}
	job := s.dl.Start(req.Items, req.Folder)
	writeJSON(w, map[string]any{"jobId": job.ID})
}

// handleJob returns a snapshot of the current download job
func (s *webServer) handleJob(w http.ResponseWriter, r *http.Request) {
	job := s.dl.Current()
	if job == nil {
		writeJSON(w, map[string]any{"state": "idle"})
		return
	}
	writeJSON(w, job)
}

// handlePickFolder resolves a save folder through the platform picker
func (s *webServer) handlePickFolder(w http.ResponseWriter, r *http.Request) {
	folder, err := pickDownloadFolder()
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, map[string]any{"folder": folder})
}
