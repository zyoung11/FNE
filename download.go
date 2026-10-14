package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// downloadItem is one track within a download job
type downloadItem struct {
	Song   songItem `json:"song"`
	Level  string   `json:"level"`
	Folder string   `json:"folder"`
	State  string   `json:"state"`
	Detail string   `json:"detail"`
}

// downloadJob tracks one batch download requested from the web UI
type downloadJob struct {
	ID     int            `json:"id"`
	Folder string         `json:"folder"`
	Items  []downloadItem `json:"items"`
	Done   int            `json:"done"`
	State  string         `json:"state"`
	mu     sync.Mutex
}

// setItem updates the state of one item inside the job
func (j *downloadJob) setItem(index int, state, detail string) {
	j.mu.Lock()
	j.Items[index].State = state
	j.Items[index].Detail = detail
	if state == "done" || state == "failed" {
		j.Done++
	}
	j.mu.Unlock()
}

// snapshot returns a copy of the job state for JSON serialization
func (j *downloadJob) snapshot() *downloadJob {
	j.mu.Lock()
	defer j.mu.Unlock()
	copyJob := &downloadJob{}
	copyJob.ID = j.ID
	copyJob.Folder = j.Folder
	copyJob.Items = append([]downloadItem(nil), j.Items...)
	copyJob.Done = j.Done
	copyJob.State = j.State
	return copyJob
}

// downloader executes download jobs sequentially and reports progress
type downloader struct {
	mu         sync.Mutex
	job        *downloadJob
	nextID     int
	client     *neteaseClient
	status     *downloadStatus
	nameFormat string
}

// newDownloader creates a downloader bound to a NetEase client and a TUI status sink
func newDownloader(client *neteaseClient, status *downloadStatus, nameFormat string) *downloader {
	return &downloader{client: client, status: status, nameFormat: nameFormat}
}

// Start creates a job for the given songs and begins downloading in the background
func (d *downloader) Start(items []downloadItem, folder string) *downloadJob {
	d.mu.Lock()
	d.nextID++
	job := &downloadJob{ID: d.nextID, Folder: folder, State: "running"}
	job.Items = make([]downloadItem, len(items))
	for i, it := range items {
		it.State = "pending"
		it.Detail = ""
		job.Items[i] = it
	}
	d.job = job
	d.mu.Unlock()
	go d.run(job)
	return job
}

// Current returns a snapshot of the latest job or nil when none exists
func (d *downloader) Current() *downloadJob {
	d.mu.Lock()
	job := d.job
	d.mu.Unlock()
	if job == nil {
		return nil
	}
	return job.snapshot()
}

// run processes all items of a job sequentially
func (d *downloader) run(job *downloadJob) {
	base := time.Now()
	for i := range job.Items {
		song := job.Items[i].Song
		folder := job.Items[i].Folder
		if folder == "" {
			folder = job.Folder
		}
		d.pushStatus(job, i, "下载中", "")
		name, err := downloadTrack(d.client, song, job.Items[i].Level, folder, d.nameFormat)
		if err != nil {
			job.setItem(i, "failed", err.Error())
			d.pushStatus(job, i, "失败", err.Error())
			continue
		}
		setFileOrderTime(filepath.Join(folder, name), base.Add(time.Duration(i)*time.Second))
		job.setItem(i, "done", name)
		d.pushStatus(job, i, "完成", name)
	}
	job.mu.Lock()
	job.State = "finished"
	job.mu.Unlock()
}

// pushStatus mirrors the job progress into the TUI status view
func (d *downloader) pushStatus(job *downloadJob, index int, state, detail string) {
	if d.status == nil {
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
	d.status.update(lines, snap.Done, len(snap.Items), "")
}

// buildOutputName formats the output file name using the configured naming scheme
func buildOutputName(format string, song songItem) string {
	if strings.HasPrefix(format, "title") {
		return sanitizeFileName(song.Name + " - " + song.Artists)
	}
	return sanitizeFileName(song.Artists + " - " + song.Name)
}

// downloadTrack downloads one track and embeds metadata and cover art
func downloadTrack(client *neteaseClient, song songItem, level, folder, nameFormat string) (string, error) {
	if err := os.MkdirAll(folder, 0755); err != nil {
		return "", err
	}
	info, err := client.SongURL(song.ID, level)
	if err != nil {
		return "", err
	}
	baseName := buildOutputName(nameFormat, song)
	if baseName == "" {
		baseName = sanitizeFileName(song.Name)
	}
	finalPath := filepath.Join(folder, baseName+"."+info.Type)
	partPath := finalPath + ".part"
	if err := fetchToFile(info.URL, partPath); err != nil {
		os.Remove(partPath)
		return "", err
	}
	var cover []byte
	if song.CoverURL != "" {
		cover = fetchBytes(song.CoverURL)
	}
	meta := &ncmMetadata{}
	meta.MusicName = song.Name
	meta.Album = song.Album
	meta.Format = info.Type
	artistJSON, _ := json.Marshal(strings.Split(song.Artists, ","))
	meta.Artist = artistJSON
	artist := parseArtist(meta.Artist)
	if info.Type == "mp3" {
		if err := embedMP3(partPath, meta, artist, cover); err != nil {
			os.Remove(partPath)
			return "", fmt.Errorf("embed mp3 metadata: %w", err)
		}
	} else {
		embedFLAC(partPath, meta, artist, cover)
	}
	if err := os.Rename(partPath, finalPath); err != nil {
		os.Remove(partPath)
		return "", err
	}
	return filepath.Base(finalPath), nil
}

// fetchToFile downloads a URL into the given file path
func fetchToFile(rawURL, path string) error {
	resp, err := http.Get(rawURL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download failed: HTTP %d", resp.StatusCode)
	}
	out, err := os.Create(path)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, resp.Body)
	return err
}

// fetchBytes downloads a URL and returns its body
func fetchBytes(rawURL string) []byte {
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(rawURL)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}
	return data
}

// sanitizeFileName removes characters that are invalid in file names
func sanitizeFileName(name string) string {
	replacer := strings.NewReplacer("/", "_", "\\", "_", ":", "_", "*", "_", "?", "_", "\"", "_", "<", "_", ">", "_", "|", "_")
	return strings.TrimSpace(replacer.Replace(name))
}
