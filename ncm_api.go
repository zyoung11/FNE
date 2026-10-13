package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	ncmWebDomain = "https://music.163.com"
	ncmAPIDomain = "https://interface3.music.163.com"
	ncmUAWeb     = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0"
	ncmUAAPI     = "NeteaseMusic 9.0.90/5038 (iPhone; iOS 16.2; zh_CN)"
)

// neteaseClient wraps the NetEase weapi and eapi endpoints with persistent cookies
type neteaseClient struct {
	cookies  map[string]string
	deviceID string
	http     *http.Client
}

// songItem holds track metadata returned by search and detail endpoints
type songItem struct {
	ID       int64  `json:"id"`
	Name     string `json:"name"`
	Artists  string `json:"artists"`
	Album    string `json:"album"`
	CoverURL string `json:"coverUrl"`
	Duration int64  `json:"duration"`
}

// albumItem holds album metadata returned by search and detail endpoints
type albumItem struct {
	ID       int64  `json:"id"`
	Name     string `json:"name"`
	Artist   string `json:"artist"`
	CoverURL string `json:"coverUrl"`
	TrackNum int    `json:"trackNum"`
}

// newNeteaseClient loads persisted cookies or prepares an anonymous session
func newNeteaseClient() *neteaseClient {
	c := &neteaseClient{
		cookies: make(map[string]string),
		http:    &http.Client{Timeout: 30 * time.Second},
	}
	c.load()
	if c.deviceID == "" {
		c.deviceID = randomHex(32)
	}
	if _, ok := c.cookies["_ntes_nuid"]; !ok {
		c.cookies["_ntes_nuid"] = randomHex(32)
	}
	return c
}

// cookieFilePath returns the path of the persisted cookie file
func cookieFilePath() (string, error) {
	dir, err := configDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "ncm_cookie.json"), nil
}

// load restores cookies and the device id from disk
func (c *neteaseClient) load() {
	path, err := cookieFilePath()
	if err != nil {
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var saved struct {
		DeviceID string            `json:"deviceId"`
		Cookies  map[string]string `json:"cookies"`
	}
	if err := json.Unmarshal(data, &saved); err != nil {
		return
	}
	c.deviceID = saved.DeviceID
	if saved.Cookies != nil {
		c.cookies = saved.Cookies
	}
}

// Save persists cookies and the device id to disk
func (c *neteaseClient) Save() error {
	path, err := cookieFilePath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(map[string]any{
		"deviceId": c.deviceID,
		"cookies":  c.cookies,
	}, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

// CookieFilePath returns the location of the persisted cookie file
func (c *neteaseClient) CookieFilePath() string {
	path, err := cookieFilePath()
	if err != nil {
		return ""
	}
	return path
}

// LoggedIn reports whether a login cookie is present
func (c *neteaseClient) LoggedIn() bool {
	return c.cookies["MUSIC_U"] != ""
}

// Account validates the current cookies and returns the account nickname
func (c *neteaseClient) Account() (string, error) {
	body, err := c.post("/api/nuser/account/get", map[string]any{}, false)
	if err != nil {
		return "", err
	}
	profile, _ := body["profile"].(map[string]any)
	if profile == nil {
		return "", fmt.Errorf("not logged in")
	}
	nickname, _ := profile["nickname"].(string)
	return nickname, nil
}

// LoginQRKey requests a new QR login key from the server
func (c *neteaseClient) LoginQRKey() (string, error) {
	body, err := c.post("/api/login/qrcode/unikey", map[string]any{"type": 1}, false)
	if err != nil {
		return "", err
	}
	key, _ := body["unikey"].(string)
	if key == "" {
		return "", fmt.Errorf("empty qr key")
	}
	return key, nil
}

// LoginQRURL returns the URL encoded inside the login QR code
func (c *neteaseClient) LoginQRURL(key string) string {
	return "https://music.163.com/login?codekey=" + url.QueryEscape(key)
}

// LoginQRCheck polls the QR login status and returns the status code
func (c *neteaseClient) LoginQRCheck(key string) (int, error) {
	body, err := c.post("/api/login/qrcode/client/login", map[string]any{"type": 1, "key": key}, false)
	if err != nil {
		return 0, err
	}
	code, _ := body["code"].(float64)
	return int(code), nil
}

// SearchSongs searches tracks by keyword
func (c *neteaseClient) SearchSongs(keyword string, limit, offset int) ([]songItem, int, error) {
	body, err := c.post("/api/cloudsearch/pc", map[string]any{
		"s":      keyword,
		"type":   1,
		"limit":  limit,
		"offset": offset,
		"total":  true,
	}, false)
	if err != nil {
		return nil, 0, err
	}
	result, _ := body["result"].(map[string]any)
	if result == nil {
		return nil, 0, nil
	}
	raw, _ := result["songs"].([]any)
	total, _ := result["songCount"].(float64)
	songs := make([]songItem, 0, len(raw))
	for _, entry := range raw {
		item := parseSongEntry(entry)
		if item != nil {
			songs = append(songs, *item)
		}
	}
	return songs, int(total), nil
}

// SearchAlbums searches albums by keyword
func (c *neteaseClient) SearchAlbums(keyword string, limit, offset int) ([]albumItem, int, error) {
	body, err := c.post("/api/cloudsearch/pc", map[string]any{
		"s":      keyword,
		"type":   10,
		"limit":  limit,
		"offset": offset,
		"total":  true,
	}, false)
	if err != nil {
		return nil, 0, err
	}
	result, _ := body["result"].(map[string]any)
	if result == nil {
		return nil, 0, nil
	}
	raw, _ := result["albums"].([]any)
	total, _ := result["albumCount"].(float64)
	albums := make([]albumItem, 0, len(raw))
	for _, entry := range raw {
		obj, _ := entry.(map[string]any)
		if obj == nil {
			continue
		}
		item := albumItem{}
		item.ID = int64FromAny(obj["id"])
		item.Name, _ = obj["name"].(string)
		item.TrackNum = int(int64FromAny(obj["size"]))
		if artist, ok := obj["artist"].(map[string]any); ok {
			item.Artist, _ = artist["name"].(string)
		}
		item.CoverURL, _ = obj["picUrl"].(string)
		albums = append(albums, item)
	}
	return albums, int(total), nil
}

// SongDetail fetches full metadata for one track
func (c *neteaseClient) SongDetail(id int64) (*songItem, error) {
	body, err := c.post("/api/v3/song/detail", map[string]any{
		"c": fmt.Sprintf(`[{"id":%d}]`, id),
	}, false)
	if err != nil {
		return nil, err
	}
	raw, _ := body["songs"].([]any)
	if len(raw) == 0 {
		return nil, fmt.Errorf("song %d not found", id)
	}
	item := parseSongEntry(raw[0])
	if item == nil {
		return nil, fmt.Errorf("song %d not found", id)
	}
	return item, nil
}

// AlbumDetail fetches album metadata and its track list
func (c *neteaseClient) AlbumDetail(id int64) (*albumItem, []songItem, error) {
	body, err := c.post(fmt.Sprintf("/api/v1/album/%d", id), map[string]any{}, false)
	if err != nil {
		return nil, nil, err
	}
	albumObj, _ := body["album"].(map[string]any)
	if albumObj == nil {
		return nil, nil, fmt.Errorf("album %d not found", id)
	}
	album := &albumItem{}
	album.ID = int64FromAny(albumObj["id"])
	album.Name, _ = albumObj["name"].(string)
	album.CoverURL, _ = albumObj["picUrl"].(string)
	album.TrackNum = int(int64FromAny(albumObj["size"]))
	if artist, ok := albumObj["artist"].(map[string]any); ok {
		album.Artist, _ = artist["name"].(string)
	}
	raw, _ := body["songs"].([]any)
	songs := make([]songItem, 0, len(raw))
	for _, entry := range raw {
		item := parseSongEntry(entry)
		if item != nil {
			songs = append(songs, *item)
		}
	}
	return album, songs, nil
}

// songURLInfo describes the downloadable stream for one track
type songURLInfo struct {
	URL   string
	Level string
	Type  string
	Size  int64
}

// SongURL requests a playable download URL at the given quality level
func (c *neteaseClient) SongURL(id int64, level string) (*songURLInfo, error) {
	body, err := c.post("/api/song/enhance/player/url/v1", map[string]any{
		"ids":        fmt.Sprintf("[%d]", id),
		"level":      level,
		"encodeType": "flac",
	}, false)
	if err != nil {
		return nil, err
	}
	raw, _ := body["data"].([]any)
	if len(raw) == 0 {
		return nil, fmt.Errorf("no url data for song %d", id)
	}
	entry, _ := raw[0].(map[string]any)
	if entry == nil {
		return nil, fmt.Errorf("no url data for song %d", id)
	}
	songURL, _ := entry["url"].(string)
	if songURL == "" || songURL == "null" {
		levelName, _ := entry["level"].(string)
		if levelName == "" {
			levelName = level
		}
		return nil, fmt.Errorf("song %d has no downloadable url at level %s", id, levelName)
	}
	info := &songURLInfo{}
	info.URL = songURL
	info.Level, _ = entry["level"].(string)
	info.Type, _ = entry["type"].(string)
	info.Size = int64FromAny(entry["size"])
	if info.Type == "" {
		info.Type = "mp3"
	}
	return info, nil
}

// parseSongEntry converts one raw search or detail entry into a songItem
func parseSongEntry(entry any) *songItem {
	obj, _ := entry.(map[string]any)
	if obj == nil {
		return nil
	}
	item := &songItem{}
	item.ID = int64FromAny(obj["id"])
	item.Name, _ = obj["name"].(string)
	item.Duration = int64FromAny(obj["dt"])
	if item.Duration == 0 {
		item.Duration = int64FromAny(obj["duration"])
	}
	var names []string
	if ar, ok := obj["ar"].([]any); ok {
		for _, a := range ar {
			if m, ok := a.(map[string]any); ok {
				if n, ok := m["name"].(string); ok {
					names = append(names, n)
				}
			}
		}
	} else if ar, ok := obj["artists"].([]any); ok {
		for _, a := range ar {
			if m, ok := a.(map[string]any); ok {
				if n, ok := m["name"].(string); ok {
					names = append(names, n)
				}
			}
		}
	}
	item.Artists = strings.Join(names, ",")
	if al, ok := obj["al"].(map[string]any); ok {
		item.Album, _ = al["name"].(string)
		item.CoverURL, _ = al["picUrl"].(string)
	} else if al, ok := obj["album"].(map[string]any); ok {
		item.Album, _ = al["name"].(string)
		item.CoverURL, _ = al["picUrl"].(string)
	}
	return item
}

// int64FromAny converts a JSON number value into int64
func int64FromAny(v any) int64 {
	switch n := v.(type) {
	case float64:
		return int64(n)
	case json.Number:
		i, _ := n.Int64()
		return i
	case string:
		var out int64
		fmt.Sscanf(n, "%d", &out)
		return out
	}
	return 0
}

// randomHex returns a random hex string of n characters
func randomHex(n int) string {
	buf := make([]byte, n/2)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}
	return hex.EncodeToString(buf)
}

// post sends an encrypted request and returns the decoded JSON object
func (c *neteaseClient) post(uri string, data map[string]any, eapiMode bool) (map[string]any, error) {
	cookie := c.requestCookies(uri)
	form := url.Values{}
	headers := map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
	}
	if eapiMode {
		header := c.eapiHeader(cookie)
		data["header"] = header
		dataJSON, err := json.Marshal(data)
		if err != nil {
			return nil, err
		}
		params, err := eapiEncrypt(uri, string(dataJSON))
		if err != nil {
			return nil, err
		}
		form.Set("params", params)
		headers["User-Agent"] = ncmUAAPI
		headers["Cookie"] = headerCookieString(header)
		return c.send(ncmAPIDomain+"/eapi/"+strings.TrimPrefix(uri, "/api/"), form, headers)
	}
	data["csrf_token"] = cookie["__csrf"]
	dataJSON, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	params, encSecKey, err := weapiEncrypt(string(dataJSON))
	if err != nil {
		return nil, err
	}
	form.Set("params", params)
	form.Set("encSecKey", encSecKey)
	headers["User-Agent"] = ncmUAWeb
	headers["Referer"] = ncmWebDomain
	headers["Cookie"] = cookieString(cookie)
	return c.send(ncmWebDomain+"/weapi/"+strings.TrimPrefix(uri, "/api/"), form, headers)
}

// send performs the HTTP POST and merges any Set-Cookie values into the session
func (c *neteaseClient) send(endpoint string, form url.Values, headers map[string]string) (map[string]any, error) {
	req, err := http.NewRequest("POST", endpoint, bytes.NewReader([]byte(form.Encode())))
	if err != nil {
		return nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	c.mergeCookies(resp.Cookies())
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	if code, ok := out["code"].(float64); ok && code != 200 && code != 801 && code != 802 && code != 803 && code != 800 {
		return nil, fmt.Errorf("api error code %v", code)
	}
	return out, nil
}

// mergeCookies stores Set-Cookie values from a response into the session
func (c *neteaseClient) mergeCookies(cookies []*http.Cookie) {
	for _, ck := range cookies {
		if ck.Name != "" {
			c.cookies[ck.Name] = ck.Value
		}
	}
}

// requestCookies builds the cookie map sent with a request
func (c *neteaseClient) requestCookies(uri string) map[string]string {
	cookie := make(map[string]string, len(c.cookies)+8)
	maps.Copy(cookie, c.cookies)
	cookie["os"] = "pc"
	cookie["osver"] = "Microsoft-Windows-10-Professional-build-19045-64bit"
	cookie["appver"] = "3.1.17.204416"
	cookie["channel"] = "netease"
	cookie["deviceId"] = c.deviceID
	cookie["__remember_me"] = "true"
	cookie["WEVNSM"] = "1.0.0"
	if cookie["_ntes_nnid"] == "" {
		cookie["_ntes_nnid"] = cookie["_ntes_nuid"] + "," + fmt.Sprintf("%d", time.Now().UnixMilli())
	}
	if !strings.Contains(uri, "login") && cookie["NMTID"] == "" {
		cookie["NMTID"] = randomHex(16)
	}
	return cookie
}

// eapiHeader builds the header object embedded into eapi request payloads
func (c *neteaseClient) eapiHeader(cookie map[string]string) map[string]string {
	header := map[string]string{
		"osver":       cookie["osver"],
		"deviceId":    c.deviceID,
		"os":          cookie["os"],
		"appver":      cookie["appver"],
		"versioncode": "140",
		"buildver":    fmt.Sprintf("%d", time.Now().Unix()),
		"resolution":  "1920x1080",
		"__csrf":      c.cookies["__csrf"],
		"channel":     "netease",
		"requestId":   fmt.Sprintf("%d_%04d", time.Now().UnixMilli(), time.Now().UnixNano()%1000),
	}
	if v := c.cookies["MUSIC_U"]; v != "" {
		header["MUSIC_U"] = v
	}
	if v := c.cookies["MUSIC_A"]; v != "" {
		header["MUSIC_A"] = v
	}
	return header
}

// cookieString joins a cookie map into a Cookie header value
func cookieString(cookie map[string]string) string {
	parts := make([]string, 0, len(cookie))
	for k, v := range cookie {
		parts = append(parts, k+"="+url.QueryEscape(v))
	}
	return strings.Join(parts, "; ")
}

// headerCookieString joins the eapi header map into a Cookie header value
func headerCookieString(header map[string]string) string {
	parts := make([]string, 0, len(header))
	for k, v := range header {
		parts = append(parts, k+"="+url.QueryEscape(v))
	}
	return strings.Join(parts, "; ")
}
